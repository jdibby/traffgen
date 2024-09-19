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

### Help Page ###
```
docker run jdibby/traffgen:latest --help
```

### Run Container Continuously ###
```
docker run --detach --restart unless-stopped jdibby/traffgen:latest
```

### Update Repo ###
```
cd traffgen && git pull
```
