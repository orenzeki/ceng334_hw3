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

    uint8_t *get_block(unsigned int block) const;
    struct ext2_super_block *get_super_block() const;
    struct ext2_group_desc *get_group_desc() const;
private:
    uint8_t *image;
    uint8_t *first_block;
    size_t len;
    unsigned int block_size;
    struct ext2_super_block *super;
    struct ext2_group_desc *group;
};

Image::Image(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) == -1) {
        perror("stat");
        throw std::runtime_error("Cannot stat file");
    }
    len = sb.st_size;

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        perror("open");
        throw std::runtime_error("Cannot open file");
    }
    image = (uint8_t *) mmap(NULL, len, PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, 0);
    if (image == (void *) -1) {
        perror("mmap");
        throw std::runtime_error("Cannot map file");
    }

    first_block = image + base_offset;
    super = (struct ext2_super_block *) first_block;
    if (super->s_magic != EXT2_SUPER_MAGIC) {
        fprintf(stderr, "Not an ext2 fs\n");
        throw std::runtime_error("Invalid filesystem");
    }
    block_size = 1024 << super->s_log_block_size;
    group = (struct ext2_group_desc *) (first_block + block_size);

    close(fd);
}

Image::~Image()
{
    munmap(image, len);
}

uint8_t *Image::get_block(unsigned int block) const
{
    return first_block + (block - 1)*block_size;
}

struct ext2_super_block *Image::get_super_block() const
{
    return super;
}

struct ext2_group_desc *Image::get_group_desc() const
{
    return group;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
        return 1;
    }
    Image img(argv[1]);

    struct ext2_super_block *super = img.get_super_block();
    std::cout << super->s_blocks_count << '\n';
    std::cout << super->s_first_ino << '\n';


    return 0;
}
