# firewall_lib/dns_parser.py
import struct
from typing import Tuple
from .dns_data import DNSData

class ParsedDNSPacket(DNSData):
    # ... (__init__ e _parse_qname como antes) ...
    def __init__(self, raw_payload: bytes):
        super().__init__()
        self.raw_payload: bytes = raw_payload
        self._parse()
    
    def _parse_qname(self, offset: int) -> Tuple[str, int]:
        # (código do _parse_qname sem alterações)
        labels = []
        current_offset = offset
        while True:
            length = self.raw_payload[current_offset]
            if length == 0:
                current_offset += 1
                break
            if (length & 0b11000000) == 0b11000000:
                raise ValueError("Ponteiros de compressão DNS não são suportados.")
            
            current_offset += 1
            label = self.raw_payload[current_offset : current_offset + length]
            labels.append(label.decode('ascii'))
            current_offset += length
        return ".".join(labels) + ".", current_offset

    def _parse(self) -> None:
        """Preenche os atributos herdados, agora incluindo o QTYPE."""
        try:
            if len(self.raw_payload) < 12: return
            
            header = struct.unpack('>HHHHHH', self.raw_payload[:12])
            self.id, self.flags, self.qdcount, _, _, _ = header
            self.recursion_desired = (self.flags & 0x0100) != 0
            
            # Analisa o nome de domínio e captura o offset onde ele termina
            self.qname, q_end_offset = self._parse_qname(12)
            
            # --- AQUI ESTÁ A MUDANÇA ---
            # O QTYPE são os 2 bytes seguintes ao QNAME.
            # O QCLASS são os 2 bytes seguintes ao QTYPE.
            if len(self.raw_payload) < q_end_offset + 4: return

            qtype_bytes = self.raw_payload[q_end_offset : q_end_offset + 2]
            self.qtype = struct.unpack('>H', qtype_bytes)[0]
            qclass_bytes = self.raw_payload[q_end_offset + 2 : q_end_offset + 4]
            self.qclass = struct.unpack('>H', qclass_bytes)[0]
            # --- FIM DA MUDANÇA ---
            
            self.is_valid = True
        except (struct.error, IndexError, UnicodeDecodeError, ValueError):
            self.is_valid = False