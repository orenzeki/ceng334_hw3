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

class Bitmap {
public:
    Bitmap(uint8_t *bmap, unsigned int block_size);

    bool is_set(int bit) const;
    void set(int bit) const;
    void clear(int bit) const;
private:
    uint8_t *bmap;
    unsigned int size;
    static constexpr auto nbits = 8 * ((int) sizeof bmap);
};

Bitmap::Bitmap(uint8_t *bmap, unsigned int block_size) :
    bmap(bmap),
    size(block_size)
{
}

bool Bitmap::is_set(int bit) const
{

}

class Image {
public:
    Image(const char *path);
    ~Image();

    /* 
     * Block numbering starts at 0, with 0 being the boot block.
     * We are not interested in the boot block, so we can say that block
     * numbering starts at 1 and the first block is the superblock.
     */

    /*
     * Use this for raw block access.
     */
    uint8_t *get_block(unsigned int block) const;
    Bitmap get_block_bitmap() const;
    Bitmap get_inode_bitmap() const;
    struct ext2_super_block *get_super_block() const;
    struct ext2_group_desc *get_group_desc() const;
private:
    /*
     * Pointer to the mmap'ed image file. This is the pointer returned by
     * mmap, therefore is the one to be munmap'ed in the end.
     */
    uint8_t *image;
    /*
     * Size of the image file, needed by mmap and munmap.
     */
    size_t image_size;
    /*
     * Pointer to block 1, the superblock. It is at image + base_offset, we
     * store it in another member for convenience.
     */
    uint8_t *first_block;
    /*
     * Block size in bytes, retrieved from the superblock.
     */
    unsigned int block_size;
    /*
     * Self explanatory.
     */
    struct ext2_super_block *super_block;
    struct ext2_group_desc *group_desc;
};

Image::Image(const char *path)
{
    struct stat sb;
    if (stat(path, &sb) == -1) {
        perror("stat");
        throw std::runtime_error("Cannot stat file");
    }
    image_size = sb.st_size;

    int fd = open(path, O_RDWR);
    if (fd == -1) {
        perror("open");
        throw std::runtime_error("Cannot open file");
    }
    image = (uint8_t *) mmap(NULL, image_size, PROT_READ | PROT_WRITE,
            MAP_SHARED, fd, 0);
    if (image == (void *) -1) {
        perror("mmap");
        throw std::runtime_error("Cannot map file");
    }

    first_block = image + base_offset;
    super_block = (struct ext2_super_block *) first_block;
    if (super_block->s_magic != EXT2_SUPER_MAGIC) {
        std::cerr << "Not an ext2 fs\n";
        throw std::runtime_error("Invalid filesystem");
    }
    block_size = 1024 << super_block->s_log_block_size;
    group_desc = (struct ext2_group_desc *) (first_block + block_size);

    close(fd);
}

Image::~Image()
{
    munmap(image, image_size);
}

uint8_t *Image::get_block(unsigned int block) const
{
    return first_block + (block - 1)*block_size;
}

struct ext2_super_block *Image::get_super_block() const
{
    return super_block;
}

struct ext2_group_desc *Image::get_group_desc() const
{
    return group_desc;
}

Bitmap Image::get_block_bitmap() const
{
    return Bitmap(get_block(group_desc->bg_block_bitmap), block_size);
}

Bitmap Image::get_inode_bitmap() const
{
    return Bitmap(get_block(group_desc->bg_inode_bitmap), block_size);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pathname>\n";
        return 1;
    }
    Image img(argv[1]);

    struct ext2_super_block *super = img.get_super_block();
    std::cout << super->s_blocks_count << '\n';
    std::cout << super->s_first_ino << '\n';

    Bitmap block_bitmap = img.get_block_bitmap();
    Bitmap inode_bitmap = img.get_inode_bitmap();

    return 0;
}
