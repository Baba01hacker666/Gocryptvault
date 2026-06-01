package types

type FileRecord struct {
	ID         string   `json:"id"`
	Filename   string   `json:"filename"`
	Size       int64    `json:"size"`
	MimeType   string   `json:"mime_type"`
	Compressed bool     `json:"compressed"`
	Chunks     []string `json:"chunks"`
	Created    int64    `json:"created"`
	Modified   int64    `json:"modified"`
}

type StatusReply struct {
	Unlocked      bool
	TimeUntilLock string
}

type KeysReply struct {
	MasterKey []byte
	MetaKey   []byte
}

type AddFileArgs struct {
	SourcePath  string
	LogicalName string
}

type ExportFileArgs struct {
	FileID  string
	DestDir string
}
