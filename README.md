# Cryptography-and-digital-watermarking-for-secure-transmission-of-images

Ce folosesc:

    pentru watermarking: DWT si DCT
    pentru criptare: RSA si AES



Pasi ai implemenatrii:

  I. Proces de watermarking
  
    • Pregatire date
    • Aplicare DWT
    • Aplicare DCT
    • Reconstructie imagine
    • Salvare imagine
    • Recuperare watermark
    
  II. Initializare proces de comunicatie
  
    • Generare chei RSA
    • Scriere cheie privata in fisier PEM
    • Scriere cheie publica in fisier PEM
    
  III. Trimitere cheia publica pentru encriptarea imaginii
  
  IV. Incepere proces de encriptare
  
    • Encriptie imagine cu AES
    • Encriptie parola cu RSA
    
  V. Primire imaginea encriptata
  
  VI. Primire parola encriptata
  
  VII. Incepere proces de decriptare
  
    • Citire cheie privata
    • Citire parola encriptata
    • Decriptare parola
    • Decriptare imagine
    
  VIII. Comparare PSNR pentru a determina criterii de performanta
  
    • Determinare PSNR dupa aplicarea watermarkului
    • Determinare PSNR dupa decriptare (comparat cu originalul)
    • Determinare grad de alterare al imaginii
    
  IX. Concluzie
  
    • A fost sau nu a fost imaginea alterata ? 
