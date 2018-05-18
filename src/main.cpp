#include "ext2.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <tuple>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

constexpr auto base_offset = 1024u;
constexpr auto ext2_block_size = 1024u;
constexpr auto ext2_n_direct = 12u;

class Bitmap {
public:
    Bitmap(uint8_t *bmap, unsigned block_size);

    bool is_set(unsigned bit) const;
    void set(unsigned bit) const;
    void clear(unsigned bit) const;
private:
    uint8_t *bmap;
    /*
     * A bitmap occupies one block on the filesystem, so the size is
     * same as the block size of the filesystem.
     */
    unsigned size;
    static constexpr auto nbits = 8 * sizeof *bmap;
};

Bitmap::Bitmap(uint8_t *bmap, unsigned block_size) :
    bmap(bmap),
    size(block_size)
{
}

/*
 * TODO: Should we add bounds checking?
 */
bool Bitmap::is_set(unsigned bit) const
{
    return bmap[bit / nbits] & (1 << (bit % nbits));
}

void Bitmap::set(unsigned bit) const
{
    bmap[bit / nbits] |= (1 << (bit % nbits));
}

void Bitmap::clear(unsigned bit) const
{
    bmap[bit / nbits] &= ~(1 << (bit % nbits));
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

    auto get_block_size() const;
    /*
     * Use this for raw block access.
     */
    uint8_t *get_block(unsigned block) const;
    /*
     * FIXME: All of our operations assume that only one block group exists
     * in the filesystem. For the purposes of this assignment, this is OK;
     * however at least check if this is actually the case and throw some
     * error if we are not going to generalize our implementation.
     */
    Bitmap get_block_bitmap() const;
    Bitmap get_inode_bitmap() const;
    struct ext2_super_block *get_super_block() const;
    struct ext2_group_desc *get_group_desc() const;
    /*
     * Get the inode table for the first block group.
     * Beware that the number of inodes here is super->s_inodes_per_group.
     */
    struct ext2_inode *get_inode_table() const;
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
    unsigned block_size;
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

auto Image::get_block_size() const
{
    return block_size;
}

/*
 * TODO: Should we add bounds checking?
 */
uint8_t *Image::get_block(unsigned block) const
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

struct ext2_inode *Image::get_inode_table() const
{
    return (struct ext2_inode *) get_block(group_desc->bg_inode_table);
}

auto find_deleted_files(const Image &image)
{
    std::vector<std::tuple<std::string, struct ext2_inode *, unsigned>> files_deleted;
    struct ext2_inode *inodes = image.get_inode_table();
    struct ext2_super_block *super = image.get_super_block();
    auto n_deleted = 0;
    for (auto i = super->s_first_ino; i < super->s_inodes_per_group; ++i) {
        if (inodes[i].i_dtime) {
            std::ostringstream filename_ss;
            filename_ss << "file";
            filename_ss << std::setfill('0') << std::setw(2) << ++n_deleted;
            files_deleted.emplace_back(filename_ss.str(), &inodes[i], i);
        }
    }
    return files_deleted;
}

/*
 * TODO: This function is a mess. The code duplication seems to be a problem.
 * Come up with a better design or refactor this shit to remove fix code duplication.
 */
bool is_recoverable(struct ext2_inode *inode, const Image &image)
{
    auto block_bitmap = image.get_block_bitmap();
    auto recoverable = true;

    /*
     * Check the direct blocks.
     */
    for (auto i = 0u; recoverable && i < ext2_n_direct && inode->i_block[i]; ++i) {
        if (block_bitmap.is_set(inode->i_block[i])) {
            recoverable = false;
        }
    }

    /*
     * Check the single indirect blocks.
     */
    if (!inode->i_block[ext2_n_direct]) {
        return recoverable;
    }
    auto block_size = image.get_block_size();
    auto single_indirect_block = (unsigned *) image.get_block(inode->i_block[ext2_n_direct]);
    for (auto i = 0u; recoverable && i < block_size && single_indirect_block[i]; ++i) {
        if (block_bitmap.is_set(single_indirect_block[i])) {
            recoverable = false;
        }
    }

    /*
     * Check the double indirect blocks.
     */
    if (!inode->i_block[ext2_n_direct + 1]) {
        return recoverable;
    }
    auto double_indirect_block = (unsigned *) image.get_block(inode->i_block[ext2_n_direct + 1]);
    for (auto i = 0u; recoverable && i < block_size && double_indirect_block[i]; ++i) {
        single_indirect_block = (unsigned *) image.get_block(double_indirect_block[i]);
        for (auto j = 0u; recoverable && j < block_size && single_indirect_block[j]; ++j) {
            if (block_bitmap.is_set(single_indirect_block[j])) {
                recoverable = false;
            }
        }
    }

    /*
     * Check the triple indirect blocks.
     */
    if (!inode->i_block[ext2_n_direct + 2]) {
        return recoverable;
    }
    auto triple_indirect_block = (unsigned *) image.get_block(inode->i_block[ext2_n_direct + 2]);
    for (auto i = 0u; recoverable && i < block_size && triple_indirect_block[i]; ++i) {
        double_indirect_block = (unsigned *) image.get_block(triple_indirect_block[i]);
        for (auto j = 0u; recoverable && j < block_size && double_indirect_block[j]; ++j) {
            single_indirect_block = (unsigned *) image.get_block(double_indirect_block[i]);
            for (auto k = 0u; recoverable && k < block_size && single_indirect_block[k]; ++k) {
                if (block_bitmap.is_set(single_indirect_block[k])) {
                    recoverable = false;
                }
            }
        }
    }

    return recoverable;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pathname>\n";
        return 1;
    }
    Image image(argv[1]);

    auto files_deleted = find_deleted_files(image);
    /*
     * Output (for each deleted file):
     * filename deletion_time num_blocks
     */
    for (const auto &file : files_deleted) {
        std::cout << std::get<0>(file) << ' ' << std::get<1>(file)->i_dtime <<
            ' ' << std::get<1>(file)->i_blocks/2 << '\n';
    }

    /*
     * We sort the vector according to the deletion time
     * of the inodes. The reason is as follows:
     * There may be multiple deleted files occupying the same blocks.
     * This only happens in the case that a file is created, deleted, another
     * one is created using the same blocks and that one is deleted too.
     * In this case, the requirements document states that the newest file
     * should be recovered. In this case the newest file also has to be the
     * deleted later than the older file.
     * If we recover the file that is deleted last (hence mark its blocks as
     * allocated), for an older file using the same blocks
     * we will find that its blocks are already allocated so we will not attempt
     * to restore it.
     */
    std::sort(files_deleted.begin(), files_deleted.end(),
            [](const auto &a, const auto &b) {
                return std::get<1>(a)->i_dtime > std::get<1>(b)->i_dtime;
    });

    for (auto &file : files_deleted) {
        struct ext2_inode *inode = std::get<1>(file);
        if (is_recoverable(inode, image)) {
            std::cout << std::get<0>(file) << '\n';
        }
    }

    return 0;
}
