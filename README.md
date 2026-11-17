# JobBoard - Backend

Server Dart sviluppato con `shelf` per il progetto JobBoard.

## Avvio del server

Aprire un terminale nella cartella `jobboard_backend` ed eseguire:

```bash
dart pub get
dart run bin/server.dart
```

Il server sarà disponibile all'indirizzo `http://localhost:8080`.

Per interromperlo, premere `Ctrl + C`.

I dati vengono salvati localmente in file JSON, mentre i curriculum PDF sono conservati nella cartella `uploads/`.
