// C++ sample: demangled frame names contain spaces and '::'.
#include <cstring>
namespace parser { struct Reader { void copy(const char *src, unsigned long n); char buf[8]; }; }
void parser::Reader::copy(const char *src, unsigned long n) { char *h = new char[8]; std::memcpy(h, src, n); buf[0] = h[0]; delete[] h; }
int main() { parser::Reader r; r.copy("0123456789abcdef", 16); return r.buf[0] == 'x'; }
