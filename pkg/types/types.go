package types

type ShardInfo struct {
	Index   int    `json:"index"`
	ShardID string `json:"shard_id"`
	NodeID  string `json:"node_id"` // Will be "local" for now
}

type ChunkInfo struct {
	Index  int         `json:"index"`
	Size   int         `json:"size"` // Original encrypted chunk size
	Shards []ShardInfo `json:"shards"`
}

type FileRecord struct {
	ID         string      `json:"id"`
	Filename   string      `json:"filename"`
	Size       int64       `json:"size"`
	MimeType   string      `json:"mime_type"`
	Compressed bool        `json:"compressed"`
	Chunks     []ChunkInfo `json:"chunks"`
	Created    int64       `json:"created"`
	Modified   int64       `json:"modified"`
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
