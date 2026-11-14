import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:bcrypt/bcrypt.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart';
import 'package:shelf_multipart/shelf_multipart.dart';

// Sessioni delle aziende attualmente autenticate
final Map<String, int> sessioni = {};

// Generatore sicuro per i token di accesso
final Random randomSicuro = Random.secure();

// Legge un elenco di oggetti da un file JSON
List<Map<String, dynamic>> leggiDati(String nome) {
  final file = File('data/$nome.json');

  if (!file.existsSync()) {
    return [];
  }

  final dati = jsonDecode(file.readAsStringSync()) as List;

  return dati
      .map((elemento) => Map<String, dynamic>.from(elemento as Map))
      .toList();
}

// Salva un elenco nel relativo file JSON
void salvaDati(String nome, List<Map<String, dynamic>> dati) {
  final file = File('data/$nome.json');
  final temporaneo = File('${file.path}.tmp');

  temporaneo.writeAsStringSync(
    const JsonEncoder.withIndent('  ').convert(dati),
    flush: true,
  );

  temporaneo.renameSync(file.path);
}

// Crea una risposta HTTP in formato JSON
Response rispostaJson(Object dati, {int stato = 200}) {
  return Response(
    stato,
    body: jsonEncode(dati),
    headers: {'content-type': 'application/json; charset=utf-8'},
  );
}

// Risposta di errore
Response errore(String messaggio, int stato) {
  return rispostaJson({'errore': messaggio}, stato: stato);
}

// Legge il JSON ricevuto dal client
Future<Map<String, dynamic>?> leggiRichiesta(Request request) async {
  try {
    final dati = jsonDecode(await request.readAsString());

    if (dati is Map<String, dynamic>) {
      return dati;
    }
  } catch (_) {
    // JSON assente o non valido
  }

  return null;
}

// Estrae un campo testuale
String campo(Map<String, dynamic> dati, String nome) {
  final valore = dati[nome];
  return valore is String ? valore.trim() : '';
}

// Genera un token casuale per la sessione aziendale
String generaToken() {
  final bytes = List<int>.generate(32, (_) => randomSicuro.nextInt(256));

  return base64UrlEncode(bytes);
}

// R1: registrazione di un'azienda
Future<Response> registraAzienda(Request request) async {
  final dati = await leggiRichiesta(request);

  if (dati == null) {
    return errore('Richiesta non valida', 400);
  }

  final nome = campo(dati, 'nome');
  final email = campo(dati, 'email').toLowerCase();
  final password = dati['password'] is String ? dati['password'] as String : '';

  final emailValida = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(email);

  if (nome.isEmpty || !emailValida) {
    return errore('Inserisci nome azienda ed email valida', 400);
  }

  if (password.length < 8 || utf8.encode(password).length > 72) {
    return errore(
      'La password deve avere almeno 8 caratteri e massimo 72 byte',
      400,
    );
  }

  final aziende = leggiDati('aziende');

  // Controllo email già registrata
  for (final azienda in aziende) {
    if (azienda['email'] == email) {
      return errore('Email già registrata', 409);
    }
  }

  // Salviamo un hash bcrypt, non la password originale
  final passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(logRounds: 12));

  final nuovaAzienda = {
    'id': DateTime.now().microsecondsSinceEpoch,
    'nome': nome,
    'email': email,
    'passwordHash': passwordHash,
  };

  aziende.add(nuovaAzienda);
  salvaDati('aziende', aziende);

  return rispostaJson({
    'messaggio': 'Azienda registrata con successo',
  }, stato: 201);
}

// R2: login aziendale
Future<Response> loginAzienda(Request request) async {
  final dati = await leggiRichiesta(request);

  if (dati == null) {
    return errore('Richiesta non valida', 400);
  }

  final email = campo(dati, 'email').toLowerCase();
  final password = dati['password'] is String ? dati['password'] as String : '';

  final aziende = leggiDati('aziende');

  Map<String, dynamic>? aziendaTrovata;

  for (final azienda in aziende) {
    if (azienda['email'] == email) {
      aziendaTrovata = azienda;
      break;
    }
  }

  if (aziendaTrovata == null ||
      !BCrypt.checkpw(password, aziendaTrovata['passwordHash'] as String)) {
    return errore('Email o password errate', 401);
  }

  final token = generaToken();
  sessioni[token] = aziendaTrovata['id'] as int;

  return rispostaJson({'token': token, 'nome': aziendaTrovata['nome']});
}

// R5: elenco pubblico degli annunci
Response elencaAnnunci(Request request) {
  final annunci = leggiDati('annunci').reversed.toList();

  return rispostaJson(annunci);
}

// R4: pubblicazione di un annuncio
Future<Response> pubblicaAnnuncio(Request request) async {
  final autorizzazione = request.headers['authorization'] ?? '';

  if (!autorizzazione.startsWith('Bearer ')) {
    return errore('Accesso non autorizzato', 401);
  }

  final token = autorizzazione.substring(7);
  final aziendaId = sessioni[token];

  if (aziendaId == null) {
    return errore('Sessione non valida', 401);
  }

  final dati = await leggiRichiesta(request);

  if (dati == null) {
    return errore('Richiesta non valida', 400);
  }

  final titolo = campo(dati, 'titolo');
  final descrizione = campo(dati, 'descrizione');

  if (titolo.isEmpty || descrizione.isEmpty) {
    return errore('Titolo e descrizione sono obbligatori', 400);
  }

  final aziende = leggiDati('aziende');

  Map<String, dynamic>? azienda;

  for (final elemento in aziende) {
    if (elemento['id'] == aziendaId) {
      azienda = elemento;
      break;
    }
  }

  if (azienda == null) {
    return errore('Azienda non trovata', 401);
  }

  final annunci = leggiDati('annunci');

  final nuovoAnnuncio = {
    'id': DateTime.now().microsecondsSinceEpoch,
    'aziendaId': aziendaId,
    'aziendaNome': azienda['nome'],
    'titolo': titolo,
    'descrizione': descrizione,
  };

  annunci.add(nuovoAnnuncio);
  salvaDati('annunci', annunci);

  return rispostaJson(nuovoAnnuncio, stato: 201);
}

// R6: ricezione e salvataggio di una candidatura
Future<Response> inviaCandidatura(Request request, String id) async {
  // Verifichiamo che l'annuncio esista
  final annuncioId = int.tryParse(id);
  final annunci = leggiDati('annunci');

  if (annuncioId == null || !annunci.any((a) => a['id'] == annuncioId)) {
    return errore('Annuncio non trovato', 404);
  }

  // Controlliamo che la richiesta contenga un form multipart
  final form = request.formData();

  if (form == null) {
    return errore('Formato della richiesta non valido', 415);
  }

  String nome = '';
  String cognome = '';
  String email = '';
  String nomeOriginale = '';
  List<int>? curriculum;

  const limitePdf = 5 * 1024 * 1024; // 5 MB

  // Leggiamo i campi e il file ricevuti dal client
  try {
    await for (final campoForm in form.formData) {
      switch (campoForm.name) {
        case 'nome':
          nome = (await campoForm.part.readString()).trim();
          break;

        case 'cognome':
          cognome = (await campoForm.part.readString()).trim();
          break;

        case 'email':
          email = (await campoForm.part.readString()).trim();
          break;

        case 'curriculum':
          nomeOriginale = campoForm.filename ?? '';

          final bytes = <int>[];

          await for (final blocco in campoForm.part) {
            if (bytes.length + blocco.length > limitePdf) {
              return errore('Il curriculum non può superare 5 MB', 413);
            }

            bytes.addAll(blocco);
          }

          curriculum = bytes;
          break;

        default:
          await campoForm.part.drain();
      }
    }
  } catch (_) {
    return errore('Impossibile leggere la candidatura', 400);
  }

  // Validazione dei dati obbligatori
  final emailValida = RegExp(r'^[^@\s]+@[^@\s]+\.[^@\s]+$').hasMatch(email);

  if (nome.isEmpty ||
      cognome.isEmpty ||
      !emailValida ||
      nome.length > 100 ||
      cognome.length > 100 ||
      email.length > 200) {
    return errore('Dati del candidato non validi', 400);
  }

  // Non utilizziamo il nome ricevuto per salvare il file
  final nomeSicuro = nomeOriginale.split(RegExp(r'[/\\]')).last;

  final bytesPdf = curriculum;

  // Controlliamo estensione e intestazione del PDF
  if (!nomeSicuro.toLowerCase().endsWith('.pdf') ||
      bytesPdf == null ||
      bytesPdf.length < 5 ||
      bytesPdf[0] != 0x25 ||
      bytesPdf[1] != 0x50 ||
      bytesPdf[2] != 0x44 ||
      bytesPdf[3] != 0x46 ||
      bytesPdf[4] != 0x2D) {
    return errore('Allega un curriculum PDF valido', 400);
  }

  // Creiamo la cartella per i curriculum
  final cartella = Directory('uploads/curriculum');
  cartella.createSync(recursive: true);

  // Nome casuale, per evitare sovrascritture e percorsi arbitrari
  final nomeSalvato = '${generaToken().replaceAll('=', '')}.pdf';

  final file = File('${cartella.path}/$nomeSalvato');

  try {
    // Salviamo fisicamente il PDF
    file.writeAsBytesSync(bytesPdf, flush: true);

    // Salviamo i dati della candidatura nel JSON
    final candidature = leggiDati('candidature');

    final nuovaCandidatura = {
      'id': DateTime.now().microsecondsSinceEpoch,
      'annuncioId': annuncioId,
      'nome': nome,
      'cognome': cognome,
      'email': email,
      'curriculumFile': nomeSalvato,
      'curriculumNome': nomeSicuro,
    };

    candidature.add(nuovaCandidatura);
    salvaDati('candidature', candidature);
  } catch (_) {
    // Evitiamo di lasciare file isolati se il salvataggio fallisce
    if (file.existsSync()) {
      file.deleteSync();
    }

    return errore('Errore durante il salvataggio', 500);
  }

  return rispostaJson({
    'messaggio': 'Candidatura inviata con successo!',
  }, stato: 201);
}

Future<void> main() async {
  // Prepara i file persistenti, solo se non esistono
  Directory('data').createSync(recursive: true);

  for (final nome in ['aziende', 'annunci', 'candidature']) {
    final file = File('data/$nome.json');

    if (!file.existsSync()) {
      file.writeAsStringSync('[]');
    }
  }

  // API del nostro server
  final router = Router()
    ..get('/', (Request request) {
      return Response.ok('Hello, World!');
    })
    ..post('/api/aziende', registraAzienda)
    ..post('/api/login', loginAzienda)
    ..get('/api/annunci', elencaAnnunci)
    ..post('/api/annunci', pubblicaAnnuncio)
    ..post('/api/annunci/<id>/candidature', inviaCandidatura);

  final handler = Pipeline()
      .addMiddleware(logRequests())
      .addHandler(router.call);

  final server = await shelf_io.serve(handler, InternetAddress.anyIPv4, 8080);

  print('Server avviato sulla porta ${server.port}');
}
