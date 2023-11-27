#  получаем длину в битах
def bit_length(value):
    return len(bin(value)[2:])  # удаляем '0b' в начале


class Crypt(object):
    def __init__(self, key, sbox):
        assert bit_length(key) <= 256
        self._key = None
        self._subkeys = None
        self.key = key
        self.sbox = sbox

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, key):
        assert bit_length(key) <= 256
        # Для генерации подключей исходный 256-битный ключ разбивается на восемь 32-битных блоков: K1…K8.
        self._key = key
        self._subkeys = [(key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]  # 8 32-битных блоков

    def _f(self, part, key):
        """Функция шифрования (выполняется в раудах)"""
        assert bit_length(part) <= 32
        assert bit_length(part) <= 32
        temp = part ^ key  # складываем по модулю
        output = 0
        # разбиваем по 4бита
        # в рез-те sbox[i][j] где i-номер шага, j-значение 4битного куска i шага
        # выходы всех восьми S-блоков объединяются в 32-битное слово
        for i in range(8):
            output |= ((self.sbox[i][(temp >> (4 * i)) & 0b1111]) << (4 * i))
            # всё слово циклически сдвигается влево (к старшим разрядам) на 11 битов.
        return ((output << 11) | (output << (32 - 11))) & 0xFFFFFFFF

    def _decrypt_round(self, left_part, right_part, round_key):
        return left_part, right_part ^ self._f(left_part, round_key)

    def encrypt(self, msg):
        """Шифрование исходного сообщения"""

        def _encrypt_round(left, right, round_key):
            return right, left ^ self._f(right, round_key)

        assert bit_length(msg) <= 64
        # открытый текст сначала разбивается на две половины
        # (младшие биты — right_path, старшие биты — left_path)
        left_part = msg >> 32
        right_part = msg & 0xFFFFFFFF
        # Выполняем 32 рауда со своим подключом Ki
        # Ключи K1… K24 являются циклическим повторением ключей K1… K8 (нумеруются от младших битов к старшим).
        for i in range(24):
            left_part, right_part = _encrypt_round(left_part, right_part, self._subkeys[i % 8])
            # Ключи K25… K32 являются ключами K1… K8, идущими в обратном порядке.
        for i in range(8):
            left_part, right_part = _encrypt_round(left_part, right_part, self._subkeys[7 - i])
        return (left_part << 32) | right_part  # сливаем половинки вместе

    def decrypt(self, crypted_msg):
        """Дешифрование криптованого сообщения
        Расшифрование выполняется так же, как и шифрование, но инвертируется порядок подключей Ki."""

        def _decrypt_round(left_part, right_part, round_key):
            return right_part ^ self._f(left_part, round_key), left_part

        assert bit_length(crypted_msg) <= 64
        left_part = crypted_msg >> 32
        right_part = crypted_msg & 0xFFFFFFFF
        for i in range(8):
            left_part, right_part = _decrypt_round(left_part, right_part, self._subkeys[i])
        for i in range(24):
            left_part, right_part = _decrypt_round(left_part, right_part, self._subkeys[(7 - i) % 8])
        return (left_part << 32) | right_part  # сливаем половинки вместе
