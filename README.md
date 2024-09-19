### Clone The Directory ###
```
git clone https://github.com/jdibby/traffgen
```

### Access New Directory
```
cd traffgen
```

### Build Container
```
docker build -t jdibby/traffgen .
```

### Run Container Continuously in Background ###
```
docker run --detach --restart unless-stopped jdibby/traffgen:latest
```

### Run Container in Foreground ###
```
docker run -it jdibby/traffgen:latest
```

### Help Page ###
```
docker run jdibby/traffgen:latest --help
```

### Update Repo ###
```
cd traffgen && git pull
```
