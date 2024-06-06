
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
 
//Các hằng số này là phần nguyên của hàm sin của các số nguyên (theo radian) nhân với 2^32. 
const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r chỉ định số lần dịch chuyển trên mỗi vòng
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// Định nghĩa hàm leftrotate
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}
 
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
 
 // Các biến này sẽ chứa giá trị hash
    uint32_t h0, h1, h2, h3;
    uint8_t *msg = NULL;

    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;
 
 // Khởi tạo biến - đếm đơn giản theo từng nibble
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
//    Tiền xử lý:
//     Nối thêm "1" bit vào tin nhắn    
//     Nối thêm bit "0" cho đến khi độ dài tin nhắn tính bằng bit ≡ 448 (MOD 512)
//     Nối thêm độ dài mod (2 ^ 64) vào tin nhắn
 
    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;
 
    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; //nối thêm bit "1"; Bit quan trọng nhất là "đầu tiên"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // nối thêm "0" bits
 
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, nhưng tránh tràn.
    to_bytes(initial_len>>29, msg + new_len + 4);
 
    // Xử lý thư trong các đoạn 512 bit liên tiếp:
    // Đối với mỗi đoạn thư 512 bit:
    for(offset=0; offset<new_len; offset += (512/8)) {
 
    ///Chia đoạn thành 16 từ 32 bit w [j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);
 
         // Khởi tạo giá trị băm cho đoạn này:
        a = h0;
        b = h1;
        c = h2;
        d = h3;
 
        // vòng lặp chính :
        for(i = 0; i<64; i++) {
 
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }
 
            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
 
        }
 
        // Thêm hàm băm của đoạn này vào kết quả:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
 
    }
 
    // dọn bộ nhớ
    free(msg);
 
    // var char digest[16] := h0 nối h1 nối h2 nối h3 //(Đầu ra ở dạng little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}
 
int main(int argc, char **argv) {
    char *msg;
    size_t len;
    int i;
    uint8_t result[16];
 
    if (argc < 2) {
        printf("usage: %s 'string'\n", argv[0]);
        return 1;
    }
    msg = argv[1];
 
    len = strlen(msg);
 
    for (i = 0; i < 1000000; i++) {
        md5((uint8_t*)msg, len, result);
    }
 
    // xuất kết quả ra màn hình
    for (i = 0; i < 16; i++)
        printf("%2.2x", result[i]);
    puts("");
 
    return 0;
}