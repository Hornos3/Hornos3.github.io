#include "hashmap.h"

template <typename K, typename V>
SwissTable<K, V>::SwissTable() {
    data = new std::vector<struct kv_pair<K, V>>(16);
    if(!data)
        throw MemoryAllocException();
    ctr_bytes = new std::vector<unsigned char>(16, 0xFF);
    if(!ctr_bytes)
        throw MemoryAllocException();
    table_size = 0;
}

template <typename K, typename V>
size_t SwissTable<K, V>::hasher(size_t data){
    unsigned char plaintext[8];
    memcpy(plaintext, &data, 8);
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, plaintext, 8);
    SHA256_Final(hash, &sha256Context);
    return *(size_t*)hash;
}

template <typename K, typename V>
size_t SwissTable<K, V>::h1(size_t hash){
    return (hash >> 4) & 0xFFFFFFFF;
}

template <typename K, typename V>
size_t SwissTable<K, V>::h2(size_t hash){
    return hash >> 57;
}

template <typename K, typename V>
int SwissTable<K, V>::insert(K key, V value){
    if(this->table_size == this->capacity())
        expand();
    return insert(key, value, this->data, this->ctr_bytes);
}

template <typename K, typename V>
size_t SwissTable<K, V>::size(){
    return this->table_size;
}

template <typename K, typename V>
size_t SwissTable<K, V>::capacity(){
    return this->data->size();
}

template <typename K, typename V>
V SwissTable<K, V>::operator[](K key) {
    V* ent = entry(key);
    if(ent)
        return *entry(key);
    throw KeyNotFoundException();
}

template <typename K, typename V>
V* SwissTable<K, V>::entry(K key) {
    return entry(key, data, ctr_bytes);
}

template <typename K, typename V>
void SwissTable<K, V>::expand() {
    table_size = 0;
    size_t ori_size = this->data->size();
    auto* real_data = (struct kv_pair<K, V>*) malloc(sizeof(struct kv_pair<K, V>) * ori_size * 2);
    auto new_data = new std::vector<struct kv_pair<K, V>>(real_data, real_data + ori_size * 2);
    if(!new_data)
        throw MemoryAllocException();
    auto new_ctr_bytes = new std::vector<unsigned char>(ori_size * 2, 0xFF);
    for(int i=0; i<ori_size; i++)
        if(!((*ctr_bytes)[i] & 0x80))
            insert((*this->data)[i].key, (*this->data)[i].value, new_data, new_ctr_bytes);
    delete this->data;
    data = new_data;
    delete this->ctr_bytes;
    ctr_bytes = new_ctr_bytes;
}

template <typename K, typename V>
V SwissTable<K, V>::remove(K key){
    size_t idx = entry_idx(key, data, ctr_bytes);
    if(idx == -1)
        throw KeyNotFoundException();
    else {
        V ret = (*this->data)[idx].value;
        (*this->ctr_bytes)[idx] = 0xFE; // deleted
        table_size--;
        return ret;
    }
}

template <typename K, typename V>
int SwissTable<K, V>::insert(K key, V value, std::vector<struct kv_pair<K, V>>* target_data, std::vector<unsigned char>* target_ctr){
    V* ent = entry(key, target_data, target_ctr);
    if(ent) {
        *ent = value;   // if key exists, substitute original value to this new one
        return INSERT_ALREADY_EXIST;
    } else {     // key not exists
        size_t insert_pos = get_insert_pos(key, target_ctr);
        (*target_data)[insert_pos] = {.key = key, .value = value};
        (*target_ctr)[insert_pos] = h2(hasher(key));
        this->table_size++;
        return INSERT_SUCCESS;
    }
}

template <typename K, typename V>
size_t SwissTable<K, V>::get_insert_pos(K key) {
    return get_insert_pos(key, this->ctr_bytes);
}

template <typename K, typename V>
size_t SwissTable<K, V>::get_insert_pos(K key, std::vector<unsigned char>* target_ctr) {
    size_t hash = hasher(key);
    size_t init_index = ((hash >> 4) & 0xFFFFFFFF) % (target_ctr->size() / 16);
    size_t index = init_index;
    while(true){
        int avail = get_first_avail_ingroup(index, target_ctr);
        if(avail >= 0)
            return avail + index * 16;
        index += 1;
        index %= target_ctr->size() / 16;
        if(index == init_index)  // actually a fatal error, the hashmap cannot be completely full
            throw TableCompletelyFullException();
    }
}

template <typename K, typename V>
int SwissTable<K, V>::get_first_avail_ingroup(size_t group){
    return get_first_avail_ingroup(group, this->ctr_bytes);
}

template <typename K, typename V>
int SwissTable<K, V>::get_first_avail_ingroup(size_t group, std::vector<unsigned char>* target_ctr){
    __m128i ctr_group = *(__m128i*)(target_ctr->data() + group * 16);
    __m128i ctr_free = _mm_set1_epi8((char)0x80);
    ctr_free = _mm_and_si128(ctr_group, ctr_free);
    int result = _mm_movemask_epi8(ctr_free);
    for(int i=0; i<16; i++){
        if(result & 1)
            return i;
        result >>= 1;
    }
    return -1;
}

template <typename K, typename V>
int SwissTable<K, V>::match_first(__m128i group, char target){
    __m128i matcher = _mm_set1_epi8(target);
    matcher = _mm_cmpeq_epi8(group, matcher);
    int result = _mm_movemask_epi8(matcher);
    for(int i=0; i<16; i++){
        if(result & 1)
            return i;
        result >>= 1;
    }
    return -1;
}

template <typename K, typename V>
std::vector<int> SwissTable<K, V>::match_all(__m128i group, char target){
    std::vector<int> ret = {};
    __m128i matcher = _mm_set1_epi8(target);
    matcher = _mm_cmpeq_epi8(group, matcher);
    int result = _mm_movemask_epi8(matcher);
    for(int i=0; i<16; i++){
        if(result & 1)
            ret.push_back(i);
        result >>= 1;
    }
    return ret;
}

template <typename K, typename V>
V* SwissTable<K, V>::entry(K key, std::vector<struct kv_pair<K, V>>* target_data, std::vector<unsigned char>* target_ctr) {
    size_t idx = entry_idx(key, target_data, target_ctr);
    if(idx == -1)
        return nullptr;
    else
        return &((*this->data)[idx].value);
}

template <typename K, typename V>
size_t SwissTable<K, V>::entry_idx(K key, std::vector<struct kv_pair<K, V>>* target_data, std::vector<unsigned char>* target_ctr){
    size_t hash = hasher(key);
    size_t init_index = h1(hash) % (target_data->size() / 16);
    size_t index = init_index;
    char ctrl = h2(hash);
    while(true){
        __m128i ctr_group = *(__m128i*)(target_ctr->data() + index * 16);
        std::vector<int> match_result = match_all(ctr_group, ctrl); // find the control byte
        for(const int& m : match_result) {
            if((*target_data)[index * 16 + m].key == key)
                return index * 16 + m;
        }
        int first_empty_idx = match_first(ctr_group, 0xFF);     // control byte not found
        if(first_empty_idx >= 0)
            return -1;
        index += 1;
        index %= target_data->size() / 16;
        if(index == init_index)   // actually a fatal error, the hashmap cannot be completely full
            return -1;
    }
}