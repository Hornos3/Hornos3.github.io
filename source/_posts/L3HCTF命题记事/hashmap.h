//
// Created by root on 24-1-6.
//

#ifndef TREASURE_HUNTER_HASHMAP_H
#define TREASURE_HUNTER_HASHMAP_H
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <emmintrin.h>

template <typename K, typename V> struct kv_pair {
    K key;
    V value;
};

template <typename K, typename V>
class SwissTable {
#define INSERT_SUCCESS 0
#define INSERT_ALREADY_EXIST 1
public:
    std::vector<struct kv_pair<K, V>>* data;
    std::vector<unsigned char>* ctr_bytes{};
    size_t table_size;

    SwissTable();

    static size_t hasher(size_t data);

    static size_t h1(size_t hash);

    static size_t h2(size_t hash);

    int insert(K key, V value);

    size_t size();

    size_t capacity();

    V operator[](K key);

    V* entry(K key);

    void expand();

    V remove(K key);

    class SwissException : std::exception {
    public:
        const char* what() const throw() override {
            return "SwissTable Exception\n";
        }
    };

    class KeyNotFoundException : SwissException {
    public:
        const char* what() const throw() override {
            return "swiss table: key not found\n";
        }
    };

    class TableCompletelyFullException : SwissException {
    public:
        const char* what() const throw() override {
            return "swiss table: Fatal error, table is now full\n";
        }
    };

    class MemoryAllocException : SwissException {
    public:
        const char* what() const throw() override {
            return "swiss table: Fatal error, failed to execute 'new'\n";
        }
    };

private:
    int insert(K key, V value, std::vector<struct kv_pair<K, V>>* target_data, std::vector<unsigned char>* target_ctr);

    size_t get_insert_pos(K key);

    size_t get_insert_pos(K key, std::vector<unsigned char>* target_ctr);

    int get_first_avail_ingroup(size_t group);

    int get_first_avail_ingroup(size_t group, std::vector<unsigned char>* target_ctr);

    int match_first(__m128i group, char target);

    std::vector<int> match_all(__m128i group, char target);

    V* entry(K key, std::vector<struct kv_pair<K, V>>* target_data, std::vector<unsigned char>* target_ctr);

    size_t entry_idx(K key, std::vector<struct kv_pair<K, V>>* target_data, std::vector<unsigned char>* target_ctr);
};

#endif //TREASURE_HUNTER_HASHMAP_H
