package commands

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func DebugCommand(log *slog.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use: "debug",
	}

	cmd.AddCommand(unpackStringIDCommand(log))

	return cmd
}

func unpackStringIDCommand(log *slog.Logger) *cobra.Command {
	byteOrderVar := newEnum([]string{"system", "le", "be"}, "system")

	cmd := &cobra.Command{
		Use:  "unpack-string-id <id>",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			idStr := args[0]
			parseBase := 10

			var byteOrder binary.ByteOrder = binary.NativeEndian
			switch byteOrderVar.Value {
			case "le":
				byteOrder = binary.LittleEndian
			case "be":
				byteOrder = binary.BigEndian
			}

			var id uint32

			if strings.HasPrefix(idStr, "0x") {
				parseBase = 16
			}

			parsed, err := strconv.ParseInt(idStr, parseBase, 33)
			if err != nil {
				return fmt.Errorf("cannot parse given numer `%s`: %w", idStr, err)
			}
			id = uint32(parsed)

			rawBytes := make([]byte, 4)

			byteOrder.PutUint32(rawBytes, id)

			if rawBytes[3]&(1<<7) != 0 {
				fmt.Println(id)
				return nil
			}

			fmt.Println(string(rawBytes))

			return nil
		},
	}

	cmd.Flags().Var(byteOrderVar, "byte-order", "binary order to decode the given value (by default uses sytems)")

	return cmd
}
