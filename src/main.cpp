#include "ext2.h"

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

constexpr auto base_offset = 1024;
constexpr auto ext2_block_size = 1024;

class Image {
public:
    Image(const char *path);
    ~Image();
private:
    uint8_t *image;
    size_t len;
};

Image::Image(const char *path)
{
    struct stat sb;
    int fd;
    if (stat(path, &sb) == -1) {
        perror("stat");
        throw std::runtime_error("Cannot stat file");
    }
    len = sb.st_size;
    if ((fd = open(path, O_RDWR)) == -1) {
        perror("open");
        throw std::runtime_error("Cannot open file");
    }
    /*
     * TODO: Decide if we will map it at 0 and use base_offset in
     * later references, or map with base_offset and be happy later.
     */
    image = (uint8_t *)mmap(NULL, len, PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, 0);
    close(fd);
}

Image::~Image()
{
    munmap(image, len);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
        return 1;
    }
    Image img(argv[1]);

    return 0;
}
