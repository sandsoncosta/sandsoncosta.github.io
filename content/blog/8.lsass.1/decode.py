input_file = 'lsass.txt'
output_file = 'output.txt'

# Abre o arquivo de saída para escrita
with open(output_file, 'w') as outfile:
    # Inicializa o buffer para armazenar as linhas
    buffer = ""

    # Lê o arquivo linha por linha
    with open(input_file, 'r') as infile:
        for line in infile:
            # Adiciona a linha atual ao buffer
            buffer += line

            # Verifica se a linha contém ICMP echo request ou icmp
            if "ICMP echo request" in line or "icmp" in line:
                # Pega o timestamp da linha atual
                timestamp = line.split()[0]

                # Dependendo do tipo de mensagem, copia os caracteres relevantes
                if "ICMP echo request" in line:
                    # Copia os últimos 560 caracteres
                    if len(buffer) >= 560:
                        outfile.write(buffer[-560:])
                elif "icmp" in line:
                    # Copia os últimos 1472 caracteres
                    if len(buffer) >= 1472:
                        outfile.write(buffer[-1472:])

                # Limpa o buffer após a escrita para evitar duplicação
                buffer = ""