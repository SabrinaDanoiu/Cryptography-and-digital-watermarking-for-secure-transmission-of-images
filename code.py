import math
import numpy 
import pywt
import os
import io
from PIL import Image
from scipy.fftpack import dct
from scipy.fftpack import idct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import random
import secrets
import zlib
import base64


#WATERMARKING PHASE ----------------------------------------------------------------------------------------------------------------------------

current_path = str(os.path.dirname(__file__))  

# Calcul PSNR (imagine originala vs imagine modificata)
def psnr(original, modified):

    # Deschidem cele doua imagini 
    original_img = Image.open(original)
    original_array = numpy.array(original_img.getdata(), dtype=numpy.float)

    modified_img = Image.open(modified)
    modified_array = numpy.array(modified_img.getdata(), dtype=numpy.float)

    # Calculam meda patratica a erorii 
    mean_squared_error = numpy.mean( (original_array - modified_array) ** 2 )

    # Returnam valoarea PSNR
    if mean_squared_error == 0:
        return 100

    PIXEL_MAX = 255.0
    return 20 * math.log10(PIXEL_MAX / math.sqrt(mean_squared_error))


# Conversie imagine si obtinere imagine sub forma de arrray
def convert_image(image_name, size):

    img = Image.open(image_name).resize((size, size), 1)
    img = img.convert('L')
    img.save(image_name)
 
    image_array = numpy.array(img.getdata(), dtype=numpy.float).reshape((size, size))             

    return image_array

# Procesarea coeficientilor imaginii ; aplicare DWT
def process_coefficients(imArray, model, level):

    coeffs=pywt.wavedec2(data = imArray, wavelet = model, level = level)
    coeffs_H=list(coeffs) 
   
    return coeffs_H

# Aplicare DCT asupra imaginii sub forma de array
def apply_dct(image_array):

    size = image_array[0].__len__()
    all_subdct = numpy.empty((size, size))

    for i in range (0, size, 8):
        for j in range (0, size, 8):
            subpixels = image_array[i:i+8, j:j+8]
            subdct = dct(dct(subpixels.T, norm="ortho").T, norm="ortho")
            all_subdct[i:i+8, j:j+8] = subdct

    return all_subdct

# Aplicare reversed DCT asupra imaginii sub forma de array
def inverse_dct(all_subdct):

    size = all_subdct[0].__len__()
    all_subidct = numpy.empty((size, size))

    for i in range (0, size, 8):
        for j in range (0, size, 8):
            subidct = idct(idct(all_subdct[i:i+8, j:j+8].T, norm="ortho").T, norm="ortho")
            all_subidct[i:i+8, j:j+8] = subidct

    return all_subidct

# Includere watermark in imagine
def embed_watermark(watermark_array, orig_image):

    watermark_array_size = watermark_array[0].__len__()
    watermark_flat = watermark_array.ravel()
    ind = 0

    for x in range (0, orig_image.__len__(), 8):

        for y in range (0, orig_image.__len__(), 8):

            if ind < watermark_flat.__len__():

                subdct = orig_image[x:x+8, y:y+8]
                subdct[5][5] = watermark_flat[ind]
                orig_image[x:x+8, y:y+8] = subdct
                ind += 1 

    return orig_image

# Obtinere imagine din array
def print_image_from_array(image_array, name):
  
    image_array_copy = image_array.clip(0, 255)
    image_array_copy = image_array_copy.astype("uint8")
    img = Image.fromarray(image_array_copy)
    img.save(name)

# Recuperare watermark din imagine
def recover_watermark(image_array, model='haar', level = 1):

    coeffs_watermarked_image = process_coefficients(image_array, model, level=level)
    dct_watermarked_coeff = apply_dct(coeffs_watermarked_image[0])
    
    watermark_array = get_watermark(dct_watermarked_coeff, 128)

    watermark_array =  numpy.uint8(watermark_array)

    # Salvare watermark
    img = Image.fromarray(watermark_array)
    img.save('./result/recovered_watermark.jpg')

# Obtinere watermark sub forma de imagine din coeficienti
def get_watermark(dct_watermarked_coeff, watermark_size):
    
    subwatermarks = []

    for x in range (0, dct_watermarked_coeff.__len__(), 8):
        for y in range (0, dct_watermarked_coeff.__len__(), 8):
            coeff_slice = dct_watermarked_coeff[x:x+8, y:y+8]
            subwatermarks.append(coeff_slice[5][5])

    watermark = numpy.array(subwatermarks).reshape(watermark_size, watermark_size)

    return watermark

# Proces de watermarking principal
def watermarking(original, watermark):

    # Initializari
    print("Incepere proces de watermarking...")
    model = 'haar'
    level = 1

    # Pregatire date
    print("Pregatire date...")
    img_array = convert_image(original, 2048)
    watermark_array = convert_image(watermark, 50)

    # Aplicare DWT 
    print("Aplicare DWT...")
    coeffs_image = process_coefficients(img_array, model, level=level)

    # Aplicare DCT
    print("Aplicare DCT...")
    dct_array = apply_dct(coeffs_image[0])
    dct_array = embed_watermark(watermark_array, dct_array)
    coeffs_image[0] = inverse_dct(dct_array)

    # Proces de reconstructie a imaginii
    print("Reconstructie imagine...")
    image_array_H=pywt.waverec2(coeffs_image, model)
    print("Salvare imagine...")
    print_image_from_array(image_array_H, './result/image_with_watermark.jpg')


    # Recuperare watermark
    print("Recuperare watermark...")
    recover_watermark(image_array = image_array_H, model=model, level = level)

    print("Finalizare proces de watermarking\n")
    return

#RSA PHASE ---------------------------------------------------------------------------------------------------------------------------------------

# Genereaza cheile RSA si le salveaza in format PEM 
def generate_keys(): 

    # Generare perechi de chei RSA 
    print("\nGenerare chei RSA...")
    new_key = RSA.generate(2048)

    # Exportare chei in format PEM
    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")

    # Scriere cheie privata in fisier
    print("Scriere cheie privata in fisier PEM...")    
    fd = open("private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    # Scriere cheie publica in fisier
    print("Scriere cheie publica in fisier PEM...")        
    fd = open("public_key.pem", "wb")
    fd.write(public_key)
    fd.close()

    # Finalizare
    print("Generarea cheilor incheiata \n")

# Encriptie imagine cu AES si parola cu RSA
def encrypt(password, filename,key_file_path):

    print("Incepere proces de encriptare...")
    print("Encriptie imagine cu AES...")  

    # Citire cheie publica din fisier      
    fd = open("public_key.pem", "rb")
    public_key = fd.read()
    fd.close()
    rsa_key = RSA.importKey(public_key)

    # Obtinere cheie pentru encriptarea AES din parola
    key = getKey(password)

    # Initializari
    chunk_size = 64 * 1024
    output_file = filename + ".enc"
    key_file = key_file_path
    file_size = str( os.path.getsize(filename) ).zfill(16)
    IV = secrets.token_bytes(16)

    # Realizare encriptie AES a imaginii
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open( filename, 'rb' ) as inputfile:
        with open( output_file, 'wb' ) as outf:
            outf.write( bytes( file_size, 'utf-8' ))
            outf.write( IV )

            while True:
                chunk = inputfile.read(chunk_size)

                if len(chunk) == 0 :
                    break
                elif len(chunk) % 16 != 0:
                   complete = ' ' * ( 16 - len(chunk) % 16 )
                   chunk += bytes( complete, 'utf-8' )

                outf.write( encryptor.encrypt(chunk) )

    # Realizare encriptie RSA a parolei            
    with open( key_file, 'wb' ) as key_xdd:
        print("Encriptie parola cu RSA...")        
        encrypted = rsa_key.encrypt(password, 32)[0]

        # Salvare encriptie in fisier
        key_xdd.write(encrypted)

    print("Finalizare proces de encriptare \n")


# Decriptarea parolei si a imaginii pe baza parolei
def decrypt(filename, output, key_file):

    print("Incepere proces de decriptare...")

    # Citire cheie privata din fisier
    print("Citire cheie privata...")
    fd = open("private_key.pem", "rb")
    private_key = fd.read()
    fd.close()
    rsakey = RSA.importKey(private_key)

    # Citirea parolei encriptata din fisier
    print("Citire parola encriptata... ")
    fd = open(key_file, "rb")
    rsa_encrypted_key = fd.read()
    fd.close()
    
    # Decriptare parola
    print("Decriptare parola...")
    decrypted_key = rsakey.decrypt(rsa_encrypted_key)

    # Obtinere cheie AES pe baza parolei
    key = getKey(decrypted_key)

    print("Decriptare imagine...")

    # Initializari
    chunk_size = 64 * 1024
    output_file = filename

    # Decriptare imagine cu AES
    with open( filename, 'rb' ) as inf:
        filesize = int( inf.read(16) )
        IV = inf.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open( output, 'wb' ) as outf:
            while True:
                chunk = inf.read(chunk_size)
                if len(chunk) == 0 :
                    break

                outf.write( decryptor.decrypt(chunk) )

            outf.truncate(filesize)

    # Finalizare decriptie
    print("Finalizare proces de decriptare \n")
 
# Obtinere cheie pe baza parolei utilizand SHA256
def getKey(password):
    hasher = SHA256.new(password)
    return hasher.digest()

#TEST PHASE --------------------------------------------------------------------------------------------------------------------------------------

def main():

    # Seturi imagini de test (0-9)
    no_dataset = 3

    # Setul imaginilor cu care lucram
    original = './dataset/' + 'original' + str(no_dataset) + '.jpg'
    watermark = './dataset/' + 'watermark'+ str(no_dataset) + '.jpg'
    modified = './result/' + 'image_with_watermark.jpg'
    encrypted = modified + ".enc"
    decrypted = './result/decrypted_' + 'image_with_watermark.jpg'
    pass_file = './result/' + 'key_file.txt'

    # Aplicam watermarkul imaginii originale 
    watermarking(original, watermark)

    print("Initializare proces de comunicatie... ")

    # Generam cheile RSA
    generate_keys()
    print("Trimitere cheia publica pentru encriptarea imaginii...\n")

    # Generam o parola pentru encriptia AES
    password = get_random_bytes(16)

    # Encriptam imaginea si parola
    encrypt(password, modified, pass_file)

    # Decriptam parola si imaginea
    print("Primire imaginea encriptata...\nPrimire parola encriptata...\n")
    decrypt(encrypted, decrypted, pass_file)

    # Analizam gradul de alterare al imaginii
    print("Comparare PSNR pentru a determina criterii de performanta...\n")

    # Aflam PSNR rezultat in urma aplicarii watermarkului
    post_watermark_psnr = psnr(original,modified)
    print('PSNR dupa aplicarea watermarkului: ' , post_watermark_psnr)

    # Aflam PSNR rezultat in urma decriptarii
    post_decryption_psnr = psnr(original,decrypted)
    print('PSNR dupa decriptare (comparat cu originalul): ' , post_decryption_psnr)

    # Aflam Gradul de alterare al imaginii
    difference_psnr = psnr(modified,decrypted)
    print('Gradul de alterare al imaginii: ' , 100 - difference_psnr, "%\n")
    if ( difference_psnr == 100 ):
        print("Imaginea NU a fost alterata! \n")
    else: 
        print("Imaginea a fost alterata! \n")

    return


if __name__ == "__main__":
  main()