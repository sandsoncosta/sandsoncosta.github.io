from PIL import Image

def resize_image(input_path, output_path, new_width, new_height=None):
    # Abrir a imagem original
    with Image.open(input_path) as img:
        original_width, original_height = img.size
        
        # Se a altura não for fornecida, calcular proporcionalmente
        if new_height is None:
            new_height = int((original_height / original_width) * new_width)

        # Redimensionar a imagem
        img_resized = img.resize((new_width, new_height), Image.LANCZOS)

        # Salvar a imagem redimensionada
        img_resized.save(output_path)

    print(f"Imagem redimensionada com sucesso! Salvo em {output_path}.")

# Caminho da imagem de entrada e saída
# input_image_path = "E:\\HUGO\\liga\\static\\images\\teenagers-lifestyle-city_23-2149196064.jpg"
input_image_path = "C:\\Users\\sands\\Downloads\\Firewall Neon e Hub de Segurança.png"
# output_image_path = "E:\\HUGO\\liga\\content\\blog\\7.com.quem.voce.anda\\featured-sample.webp"
output_image_path = "F:\\HUGO\\blog\\content\\blog\\12.anonymous.logon\\featured-sample.webp"

# Largura e altura oficial
new_width = 1120
new_height = 640  # Defina a altura, ou deixe None para calcular automaticamente

# Alternativa
#new_width = 1349
#new_height = 768


# Chamar a função para redimensionar
resize_image(input_image_path, output_image_path, new_width, new_height)
