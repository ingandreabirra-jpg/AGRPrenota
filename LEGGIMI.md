# Prenotazioni — versione online

Pagina con tre livelli di accesso (Titolare, 4 Istruttori, Clienti illimitati) e calendario.
Il controllo degli accessi e dei dati avviene sul **server**: un cliente riceve dal server solo le proprie prenotazioni.

## Accessi
- **Titolare**: password in `ADMIN_PASSWORD`.
- **Istruttori 1–4**: all'inizio `Istruttore1` … `Istruttore4`. Il Titolare le cambia dalla scheda "Istruttori" (conviene farlo subito).
- **Clienti**: il Titolare li crea in "Clienti"; il sistema genera un codice di 8 caratteri da comunicare al cliente.

## Mettere online con il vostro indirizzo
Serve un servizio che esegua Node.js (o Docker) con un **disco persistente** per il database
(es. Render, Railway, Fly.io oppure un VPS). Passi generali:
1. Caricare questa cartella su un repository (GitHub) oppure usare il Dockerfile.
2. Impostare le variabili di `.env.example`. Comando di avvio: `npm start`.
3. Collegare un disco persistente e puntare `DB_PATH` a quel disco (senza disco i dati si perdono ad ogni riavvio).
4. Aggiungere il dominio personalizzato (es. `prenotazioni.vostrosito.it`) dalle impostazioni del servizio
   e creare il record DNS che indica. Il certificato HTTPS è di solito automatico.

Prova in locale: `npm install`, poi `ADMIN_PASSWORD=... SESSION_SECRET=... node server.js` e aprire http://localhost:3000

## Sicurezza
- Password cifrate (scrypt); accesso con cookie protetto, valido 12 ore; blocco dopo 10 tentativi errati in 15 minuti.
- Usare sempre HTTPS. Fare copie di sicurezza del file del database.
- Il codice cliente è l'unica credenziale del cliente: comunicarlo in modo riservato.
