# firewall_lib/dns_response_crafter.py
# -*- coding: utf-8 -*-

import socket
from scapy.layers.inet import UDP
from scapy.packet import Packet
from .dns_parser import ParsedDNSPacket

class DNSResponseCrafter:
    """Uma classe utilitária para criar pacotes de resposta DNS."""

    @staticmethod
    def create_block_response(packet: ParsedDNSPacket, block_ip_v4: str) -> Packet:
        """
        Cria uma resposta de bloqueio que espelha o QTYPE da requisição original.
        :param packet: O objeto ParsedDNSPacket da requisição original.
        :param block_ip_v4: O endereço IPv4 para usar no bloqueio (ex: "0.0.0.0").
        """
        if not packet.is_valid:
            raise ValueError("Não é possível criar resposta para um pacote inválido.")

        # --- INÍCIO DA NOVA LÓGICA ---
        
        # Constrói o cabeçalho da resposta, que é maioritariamente comum
        dns_header = packet.id.to_bytes(2, 'big') + b'\x81\x80' # ID + Flags
        dns_header += packet.qdcount.to_bytes(2, 'big') + b'\x00\x01' # QDCOUNT + ANCOUNT=1
        dns_header += b'\x00\x00\x00\x00' # NSCOUNT + ARCOUNT

        # Constrói a seção de pergunta, que também é comum
        qname_bytes = b''.join(len(label).to_bytes(1, 'big') + label.encode('ascii') for label in packet.qname.rstrip('.').split('.')) + b'\x00'
        question_section = qname_bytes + packet.qtype.to_bytes(2, 'big') + packet.qclass.to_bytes(2, 'big')

        # Constrói a seção de resposta baseada no QTYPE original
        answer_section = b'\xc0\x0c' # Ponteiro para o nome na pergunta
        
        # Copia o QTYPE e QCLASS da requisição para a resposta
        answer_section += packet.qtype.to_bytes(2, 'big')
        answer_section += packet.qclass.to_bytes(2, 'big')
        answer_section += (60).to_bytes(4, 'big') # TTL de 60 segundos

        # Lógica para dados e tamanho dos dados (RDATA e RDLENGTH)
        if packet.qtype == 28: # AAAA (IPv6)
            rdata = socket.inet_pton(socket.AF_INET6, "::1") # Bloqueia para o localhost IPv6
            rdlength = len(rdata)
        else: # Padrão para A (IPv4) e outros tipos
            # Para MX, TXT, etc., responder com um registro A para 0.0.0.0 é uma
            # forma eficaz de bloqueio, pois a aplicação cliente não receberá
            # o tipo de registro que esperava.
            rdata = bytes(map(int, block_ip_v4.split('.')))
            rdlength = len(rdata)
        
        answer_section += rdlength.to_bytes(2, 'big')
        answer_section += rdata

        # Junta todas as partes
        dns_payload = dns_header + question_section + answer_section
        
        return UDP(dns_payload)
        # --- FIM DA NOVA LÓGICA ---