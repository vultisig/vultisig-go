#!/bin/bash

# The following is and example of how to copy local shares to the plugin and verifier for development/testing purposes
./main dev copy share1.vult share2.vult \
--plugin-minio-access-key minioadmin  \
--plugin-minio-secret-key minioadmin  \
--plugin-minio-endpoint http://localhost:9000  \
--plugin-minio-region us-east-1  \
--plugin-minio-bucket vultisig-plugin  \
--verifier-minio-access-key minioadmin  \
--verifier-minio-secret-key minioadmin  \
--verifier-minio-endpoint http://localhost:8000  \
--verifier-minio-region us-east-1  \
--verifier-minio-bucket vultisig-verifier  \
--publickey 03a1a78bb50bd7acc6f0a56778b7f6529192dbe05e85b07a828b9d0941694e2945 \
--pluginid vultisig-fees-feee