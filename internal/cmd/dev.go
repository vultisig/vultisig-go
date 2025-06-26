package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"
)

type copyCmdArgType struct {
	pluginMinioEndpoint  string
	pluginMinioAccessKey string
	pluginMinioSecretKey string
	pluginMinioBucket    string
	pluginMinioRegion    string

	verifierMinioEndpoint  string
	verifierMinioAccessKey string
	verifierMinioSecretKey string
	verifierMinioBucket    string
	verifierMinioRegion    string

	ecdsapublickey string
	pluginid       string
}

var copyCmdArgs copyCmdArgType = copyCmdArgType{}

var devCmd = &cobra.Command{
	Use:   "dev",
	Short: "dev commands",
	Long:  "dev commands. Only for testing functionality locally. For real use cases please use reshare",
}

var copyCmd = &cobra.Command{
	Use:   "copy [file-1-path] [file-2-path]",
	Short: "simple way to copy 2 keyshares from a local directory to plugin and verifier",
	Long:  "this should only be used to testing functionality locally. For real use cases please use reshare",
	Args:  cobra.ExactArgs(2),
	RunE:  runCopy,
}

func init() {
	devCmd.AddCommand(copyCmd)
	rootCmd.AddCommand(devCmd)

	copyCmd.Flags().StringVar(&copyCmdArgs.pluginMinioEndpoint, "plugin-minio-endpoint", "https://plugin.vultisig.com", "Plugin MinIO endpoint")
	copyCmd.Flags().StringVar(&copyCmdArgs.pluginMinioAccessKey, "plugin-minio-access-key", "", "Plugin MinIO access key")
	copyCmd.Flags().StringVar(&copyCmdArgs.pluginMinioSecretKey, "plugin-minio-secret-key", "", "Plugin MinIO secret key")
	copyCmd.Flags().StringVar(&copyCmdArgs.pluginMinioBucket, "plugin-minio-bucket", "", "Plugin MinIO bucket")
	copyCmd.Flags().StringVar(&copyCmdArgs.pluginMinioRegion, "plugin-minio-region", "", "Plugin MinIO region")

	copyCmd.Flags().StringVar(&copyCmdArgs.verifierMinioEndpoint, "verifier-minio-endpoint", "https://verifier.vultisig.com", "Verifier MinIO endpoint")
	copyCmd.Flags().StringVar(&copyCmdArgs.verifierMinioAccessKey, "verifier-minio-access-key", "", "Verifier MinIO access key")
	copyCmd.Flags().StringVar(&copyCmdArgs.verifierMinioSecretKey, "verifier-minio-secret-key", "", "Verifier MinIO secret key")
	copyCmd.Flags().StringVar(&copyCmdArgs.verifierMinioBucket, "verifier-minio-bucket", "", "Verifier MinIO bucket")
	copyCmd.Flags().StringVar(&copyCmdArgs.verifierMinioRegion, "verifier-minio-region", "", "Verifier MinIO region")

	copyCmd.Flags().StringVar(&copyCmdArgs.ecdsapublickey, "publickey", "", "ECDSA public key")
	copyCmd.Flags().StringVar(&copyCmdArgs.pluginid, "pluginid", "", "Plugin ID")
}

func runCopy(cmd *cobra.Command, args []string) error {
	fmt.Println(" Reading file 1 ")
	file1data := readFile(args[0])
	fmt.Println(" File 1 size: ", len(file1data))
	fmt.Println(hex.EncodeToString(file1data))
	fmt.Println(" Reading file 2 ")
	file2data := readFile(args[1])
	fmt.Println(" File 2 size: ", len(file2data))
	fmt.Println(hex.EncodeToString(file2data))

	fmt.Println(" -------------------------------- ")
	fn := fmt.Sprintf("%s-%s.vult", copyCmdArgs.ecdsapublickey, copyCmdArgs.pluginid)
	fmt.Println("New file name: ", fn)
	fmt.Println(" -------------------------------- ")

	if err := uploadFile(fn, file1data, copyCmdArgs.pluginMinioEndpoint, copyCmdArgs.pluginMinioAccessKey, copyCmdArgs.pluginMinioSecretKey, copyCmdArgs.pluginMinioBucket, copyCmdArgs.pluginMinioRegion); err != nil {
		fmt.Println(" -------------------------------- ")
		fmt.Println("Failed to upload file 1")
		fmt.Println(" -------------------------------- ")
		return fmt.Errorf("failed to upload file %s: %w", args[0], err)
	} else {
		fmt.Println(" -------------------------------- ")
		fmt.Println("File 1 uploaded successfully")
		fmt.Println(" -------------------------------- ")
	}

	if err := uploadFile(fn, file2data, copyCmdArgs.verifierMinioEndpoint, copyCmdArgs.verifierMinioAccessKey, copyCmdArgs.verifierMinioSecretKey, copyCmdArgs.verifierMinioBucket, copyCmdArgs.verifierMinioRegion); err != nil {
		fmt.Println(" -------------------------------- ")
		fmt.Println("Failed to upload file 2")
		fmt.Println(" -------------------------------- ")
		return fmt.Errorf("failed to upload file %s: %w", args[1], err)
	} else {
		fmt.Println(" -------------------------------- ")
		fmt.Println("File 2 uploaded successfully")
		fmt.Println(" -------------------------------- ")
	}

	return nil
}

func readFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Errorf("failed to read file %s: %w", path, err)
		os.Exit(1)
	}

	return b
}

func uploadFile(fn string, data []byte, endpoint string, accessKey string, secretKey string, bucket string, region string) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)

	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true // Required for MinIO/localstack
	})

	_, err = client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &fn,
		Body:   bytes.NewReader(data),
	})

	return err
}
