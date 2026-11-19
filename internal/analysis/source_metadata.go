package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Vivirinter/layerclue/internal/acquire"
	"github.com/Vivirinter/layerclue/internal/casefile"
	"github.com/Vivirinter/layerclue/internal/custody"
	"github.com/Vivirinter/layerclue/internal/evidence"
	"github.com/Vivirinter/layerclue/internal/model"
)

const collectionJournalSchema = "layerclue.acquisition/v1"

func attachSourceMetadata(ctx context.Context, c *casefile.Case, rep *model.Report) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := evidence.ReadFile(c.Root, custody.AcquisitionFile, custody.MaxInventoryBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var header map[string]json.RawMessage
	if err := evidence.DecodeInventoryJSON(data, &header); err != nil {
		return err
	}
	var schema string
	if err := evidence.DecodeJSON(header["schema"], &schema); err != nil {
		return err
	}
	var records map[string]acquire.SourceRecord
	switch schema {
	case collectionJournalSchema:
		records, err = collectionRecords(ctx, c, data)
	case acquire.JournalSchema:
		records, err = acquire.DecodeJournalMetadata(ctx, data, c.ContainerID)
	default:
		return errors.New("unsupported acquisition journal schema")
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	journalHash := "sha256:" + hex.EncodeToString(sum[:])
	// Stage all attachments before mutating the report: a corrupt second record
	// must not leave a first record looking successfully validated.
	type attachment struct {
		location *model.Location
		record   *model.OriginalMetadata
		fact     model.Fact
	}
	var pending []attachment
	for _, loc := range []*model.Location{rep.Visible, rep.Image} {
		if loc == nil {
			continue
		}
		record, ok := records[loc.CapturedPath]
		if !ok {
			continue
		} // Generated parent directories may have no source record.
		binding, objectHash, err := bindSourceRecord(ctx, c.Root, loc, record)
		if err != nil {
			return err
		}
		if binding == "" {
			continue
		} // Special objects are not reinterpreted as regular files.
		id := "source-metadata-" + strconv.Itoa(len(rep.Facts)+len(pending)+1)
		original := &model.OriginalMetadata{
			Metadata: model.FileMetadata{Mode: os.FileMode(record.Mode).String(), ModeBits: record.Mode, UID: record.UID, GID: record.GID, MtimeNS: record.MtimeNS},
			Artifact: custody.AcquisitionFile, JournalSchema: schema, JournalSHA256: journalHash, SourcePath: record.Source,
			Binding: binding, ObjectSHA256: objectHash, Scope: model.RecordedMetadataScope, Evidence: id,
		}
		fact := model.Fact{ID: id, Kind: "source_metadata_record", Source: model.Source{Artifact: custody.AcquisitionFile, Path: loc.CapturedPath}, Strength: model.Observed,
			Value: map[string]any{"journal_sha256": journalHash, "source_path": record.Source, "binding": binding, "object_sha256": objectHash, "mode": original.Metadata.Mode, "mode_bits": record.Mode, "uid": record.UID, "gid": record.GID, "mtime_ns": strconv.FormatInt(record.MtimeNS, 10)}}
		pending = append(pending, attachment{loc, original, fact})
	}
	for _, item := range pending {
		item.location.OriginalMetadata = item.record
		rep.Facts = append(rep.Facts, item.fact)
	}
	return nil
}

func collectionRecords(ctx context.Context, c *casefile.Case, data []byte) (map[string]acquire.SourceRecord, error) {
	var journal struct {
		Schema    string          `json:"schema"`
		Inventory json.RawMessage `json:"source_inventory"`
		Transform string          `json:"transform"`
	}
	if err := evidence.DecodeInventoryJSON(data, &journal); err != nil {
		return nil, err
	}
	if journal.Schema != collectionJournalSchema || journal.Transform == "" || len(journal.Transform) > 4096 {
		return nil, errors.New("invalid collection journal header")
	}
	seal, err := custody.Decode(journal.Inventory)
	if err != nil {
		return nil, err
	}
	records := make(map[string]acquire.SourceRecord, len(seal.Inventory.Entries))
	children := make(map[string][]string)
	for _, e := range seal.Inventory.Entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if evidence.Local(e.Path) != nil || path.Clean(e.Path) != e.Path || len(e.Path) > 4096 || !utf8.ValidString(e.Path) || len(strings.Split(e.Path, "/")) > 129 {
			return nil, errors.New("invalid collection record address")
		}
		if _, duplicate := records[e.Path]; duplicate {
			return nil, errors.New("duplicate collection record address")
		}
		mode := os.FileMode(e.Mode)
		if !acquire.ValidRecordedMode(mode) {
			return nil, errors.New("collection record has unknown mode bits")
		}
		if e.Kind == "file" && (!mode.IsRegular() || e.Size < 0 || !plainHash(e.SHA256)) || e.Kind == "directory" && !mode.IsDir() || e.Kind == "symlink" && mode&os.ModeSymlink == 0 {
			return nil, errors.New("collection record type mismatch")
		}
		if e.Kind != "file" && e.Kind != "directory" && e.Kind != "symlink" {
			return nil, errors.New("unsupported collection record type")
		}
		records[e.Path] = acquire.SourceRecord{Source: e.Path, Kind: e.Kind, Mode: e.Mode, UID: e.UID, GID: e.GID, MtimeNS: e.MtimeNS, Size: e.Size, SHA256: e.SHA256}
		if e.Path != "." {
			parent := path.Dir(e.Path)
			children[parent] = append(children[parent], path.Base(e.Path))
		}
	}
	for address, names := range children {
		sort.Strings(names)
		record, ok := records[address]
		if !ok || record.Kind != "directory" {
			return nil, errors.New("collection record has no directory parent")
		}
		record.ChildrenSHA256 = childrenHash(names)
		records[address] = record
	}
	for address, record := range records {
		if record.Kind == "directory" && record.ChildrenSHA256 == "" {
			record.ChildrenSHA256 = childrenHash(nil)
			records[address] = record
		}
	}
	// A journal copied from another case must not be accepted solely because a
	// selected executable happens to contain the same bytes. Bind the case's
	// control artifacts as well; this still does not authenticate the source.
	for _, control := range []struct {
		path  string
		limit int64
	}{
		{c.MountinfoRef, evidence.MaxMountinfoBytes},
		{c.MetadataRef, evidence.MaxDatabaseBytes},
		{c.DockerInspect, evidence.MaxManifestBytes},
	} {
		if control.path == "" {
			continue
		}
		if err := bindControlArtifact(ctx, c.Root, control.path, control.limit, records); err != nil {
			return nil, err
		}
	}
	_, err = evidence.Lstat(c.Root, "case.json")
	if err == nil {
		if err := bindControlArtifact(ctx, c.Root, "case.json", evidence.MaxManifestBytes, records); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	} else if _, recorded := records["case.json"]; recorded {
		return nil, errors.New("recorded case manifest is missing")
	}
	return records, nil
}

func bindControlArtifact(ctx context.Context, root, address string, limit int64, records map[string]acquire.SourceRecord) error {
	record, ok := records[address]
	if !ok || record.Kind != "file" {
		return errors.New("source inventory has no matching case control artifact")
	}
	f, err := evidence.OpenRegular(root, address)
	if err != nil {
		return err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := evidence.Copy(ctx, h, f, limit)
	if err != nil {
		return err
	}
	after, err := evidence.Lstat(root, address)
	if err != nil {
		return err
	}
	if n != record.Size || hex.EncodeToString(h.Sum(nil)) != record.SHA256 || !evidence.SameState(before, after) {
		return errors.New("source inventory differs from case control artifact")
	}
	return nil
}

func bindSourceRecord(ctx context.Context, root string, loc *model.Location, record acquire.SourceRecord) (string, string, error) {
	if record.Kind != loc.Type {
		return "", "", errors.New("source metadata record type differs from captured object")
	}
	switch record.Kind {
	case "file":
		if loc.SHA256 == "" || record.Size != loc.Size || record.SHA256 != loc.SHA256 {
			return "", "", errors.New("source metadata record does not match captured file bytes")
		}
		return "file_sha256", record.SHA256, nil
	case "directory":
		before, err := evidence.Lstat(root, loc.CapturedPath)
		if err != nil {
			return "", "", err
		}
		dir, err := evidence.OpenDir(root, loc.CapturedPath)
		if err != nil {
			return "", "", err
		}
		defer dir.Close()
		pinned, err := dir.Stat()
		if err != nil || !evidence.SameState(before, pinned) {
			return "", "", errors.New("directory changed before source metadata binding")
		}
		var names []string
		for {
			if err := ctx.Err(); err != nil {
				return "", "", err
			}
			batch, err := dir.Readdirnames(256)
			names = append(names, batch...)
			if len(names) > custody.MaxEntries {
				return "", "", evidence.ErrLimit
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", "", err
			}
		}
		for _, name := range names {
			if !utf8.ValidString(name) {
				return "", "", errors.New("non-UTF8 directory name")
			}
		}
		sort.Strings(names)
		after, err := evidence.Lstat(root, loc.CapturedPath)
		if err != nil {
			return "", "", err
		}
		if !evidence.SameState(before, after) || childrenHash(names) != record.ChildrenSHA256 {
			return "", "", errors.New("source metadata record does not match captured directory children")
		}
		return "directory_children_sha256", record.ChildrenSHA256, nil
	}
	return "", "", nil
}

func childrenHash(names []string) string {
	data, _ := json.Marshal(names)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func plainHash(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}

// Keep the optional journal failure visible without changing byte/path facts.
func addSourceMetadata(ctx context.Context, c *casefile.Case, rep *model.Report) error {
	if err := attachSourceMetadata(ctx, c, rep); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rep.Missing = append(rep.Missing, fmt.Sprintf("source metadata journal could not be bound: %s", err))
		rep.Incomplete = true
	}
	return nil
}
