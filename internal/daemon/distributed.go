package daemon

import (
	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
	"github.com/Baba01hacker666/Gocryptvault/pkg/security"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
)

func (d *Daemon) AddFileDistributed(args *types.DistAddArgs, reply *bool) error {
	if err := d.beginOp(); err != nil { return err }
	defer d.endOp()

	tlsConfig, err := security.LoadTLSConfig(args.CA, args.Cert, args.Key, false)
	if err != nil { return err }

	c, _ := client.NewClient()
	err = c.AddFileDistributed(args.SourcePath, args.LogicalName, args.CoordAddr, tlsConfig, args.Hidden, args.HiddenPass)
	if err != nil {
		*reply = false
		return err
	}
	*reply = true
	return nil
}

func (d *Daemon) ExportFileDistributed(args *types.DistExportArgs, reply *bool) error {
	if err := d.beginOp(); err != nil { return err }
	defer d.endOp()

	tlsConfig, err := security.LoadTLSConfig(args.CA, args.Cert, args.Key, false)
	if err != nil { return err }

	c, _ := client.NewClient()
	err = c.ExportFileDistributed(args.FileID, args.DestDir, args.CoordAddr, tlsConfig, args.Hidden, args.HiddenPass)
	if err != nil {
		*reply = false
		return err
	}
	*reply = true
	return nil
}

func (d *Daemon) ListFilesDistributed(args *types.DistListArgs, reply *[]*types.FileRecord) error {
	if err := d.beginOp(); err != nil { return err }
	defer d.endOp()

	tlsConfig, err := security.LoadTLSConfig(args.CA, args.Cert, args.Key, false)
	if err != nil { return err }

	c, _ := client.NewClient()
	files, err := c.ListFilesDistributed(args.CoordAddr, tlsConfig, args.Hidden, args.HiddenPass)
	if err != nil {
		return err
	}
	*reply = files
	return nil
}

func (d *Daemon) DeleteFileDistributed(args *types.DistDeleteArgs, reply *bool) error {
	if err := d.beginOp(); err != nil { return err }
	defer d.endOp()

	tlsConfig, err := security.LoadTLSConfig(args.CA, args.Cert, args.Key, false)
	if err != nil { return err }

	c, _ := client.NewClient()
	err = c.DeleteFileDistributed(args.FileID, args.CoordAddr, tlsConfig, args.Hidden, args.HiddenPass)
	if err != nil {
		*reply = false
		return err
	}
	*reply = true
	return nil
}
