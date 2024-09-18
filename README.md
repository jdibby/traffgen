### Clone The Directory ###
```
git clone https://github.com/jdibby/traffgen
```

### Access New Directory
cd traffgen

### Build Container
docker build -t jdibby/traffgen .

### Help Pages ###
docker run --restart unless-stopped jdibby/traffgen:latest --help

### Reccomended Flags For Running Container
--restart unless-stopped jdibby/traffgen:latest
