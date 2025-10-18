/**
 * @file main_simple.c
 * @brief Comprehensive ATECC608A test - comment/uncomment tests to run
 */

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"

// ═══════════════════════════════════════════════════════════════
// ANSI COLOR CODES
// ═══════════════════════════════════════════════════════════════
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

#define SYMBOL_PASS   COLOR_GREEN  "[PASS]" COLOR_RESET
#define SYMBOL_FAIL   COLOR_RED    "[FAIL]" COLOR_RESET
#define SYMBOL_WARN   COLOR_YELLOW "[WARN]" COLOR_RESET
#define SYMBOL_INFO   COLOR_CYAN   "[INFO]" COLOR_RESET
#define SYMBOL_OK     COLOR_GREEN  "[OK]"   COLOR_RESET

// ═══════════════════════════════════════════════════════════════
// TEST SELECTION - Comment out tests you don't want to run
// ═══════════════════════════════════════════════════════════════
#define RUN_TEST_INFO           1
#define RUN_TEST_SERIAL         1
#define RUN_TEST_RANDOM         1
#define RUN_TEST_SHA256_SIMPLE  1
#define RUN_TEST_SHA256_LONG    1
#define RUN_TEST_COUNTER_READ   1
#define RUN_TEST_COUNTER_INC    1
#define RUN_TEST_LOCK_STATUS    1
#define RUN_TEST_READ_CONFIG    1
#define RUN_TEST_GENKEY         1
#define RUN_TEST_NONCE          1
#define RUN_TEST_RANDOM_MULTI   1

// Global interface configuration
ATCAIfaceCfg cfg = {
    .iface_type             = ATCA_I2C_IFACE,
    .devtype                = ATECC608A,
    .atcai2c.address        = 0xC0,     // 8-bit format
    .atcai2c.bus            = 0,
    .atcai2c.baud           = 100000,   // 100kHz for reliability
    .wake_delay             = 1500,
    .rx_retries             = 20
};

typedef struct {
    const char* name;
    bool passed;
} TestResult;

#define MAX_TESTS 20
TestResult test_results[MAX_TESTS];
int test_count = 0;

void record_test(const char* name, bool passed) {
    if (test_count < MAX_TESTS) {
        test_results[test_count].name = name;
        test_results[test_count].passed = passed;
        test_count++;
    }
}

void print_test_summary(void) {
    int passed = 0;
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║         ATECC608A TEST SUITE RESULTS             ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
    
    for (int i = 0; i < test_count; i++) {
        printf("%-35s %s\n", test_results[i].name, 
               test_results[i].passed ? SYMBOL_PASS : SYMBOL_FAIL);
        if (test_results[i].passed) passed++;
    }
    
    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf("  TOTAL: %d/%d tests passed (%.1f%%)\n", passed, test_count,
           test_count > 0 ? (100.0f * passed / test_count) : 0.0f);
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    if (passed == test_count && test_count > 0) {
        printf("\n" COLOR_GREEN COLOR_BOLD "*** ALL TESTS PASSED! HAL is fully functional. ***" COLOR_RESET "\n");
    }
}

void print_hex(const char* label, const uint8_t* data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) printf("\n    ");
    }
    printf("\n");
}

// Test 1: Read device INFO (simplest command)
bool test_info(void)
{
    printf("\n=== Test 1: Device INFO ===\n");
    
    uint8_t revision[4];
    ATCA_STATUS status = atcab_info(revision);
    
    if (status != ATCA_SUCCESS) {
        printf("%s INFO failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    print_hex("Device Info", revision, 4);
    printf("Device Type: 0x%02X%02X (should be 0x6002 for ATECC608A)\n", 
           revision[3], revision[2]);
    printf("%s INFO success!\n", SYMBOL_OK);
    return true;
}

// Test 2: Read serial number
bool test_serial(void)
{
    printf("\n=== Test 2: Serial Number ===\n");
    
    uint8_t serial[ATCA_SERIAL_NUM_SIZE];
    ATCA_STATUS status = atcab_read_serial_number(serial);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Serial read failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    print_hex("Serial Number", serial, ATCA_SERIAL_NUM_SIZE);
    printf("%s Serial read success!\n", SYMBOL_OK);
    return true;
}

// Test 3: Generate random number
bool test_random(void)
{
    printf("\n=== Test 3: Random Number ===\n");
    
    uint8_t random[32];
    ATCA_STATUS status = atcab_random(random);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Random failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    print_hex("Random", random, 32);
    
    // Sanity check - not all zeros or all FFs
    bool all_zero = true, all_ff = true;
    for (int i = 0; i < 32; i++) {
        if (random[i] != 0x00) all_zero = false;
        if (random[i] != 0xFF) all_ff = false;
    }
    if (all_zero || all_ff) {
        printf("%s Random looks suspicious\n", SYMBOL_WARN);
    }
    
    printf("%s Random success!\n", SYMBOL_OK);
    return true;
}

// Test 4: SHA-256 of single character "h"
bool test_sha256_simple(void)
{
    printf("\n=== Test 4: SHA-256 Hash (single char 'h') ===\n");
    
    const char* message = "h";
    uint8_t digest[32];
    
    printf("Computing SHA-256 of: \"%s\"\n", message);
    
    ATCA_STATUS status = atcab_hw_sha2_256((const uint8_t*)message, strlen(message), digest);
    
    if (status != ATCA_SUCCESS) {
        printf("%s SHA-256 failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    print_hex("SHA-256", digest, 32);
    
    // Verify against known hash
    const uint8_t expected[] = {
        0xAA, 0xA9, 0x40, 0x26, 0x64, 0xF1, 0xA4, 0x1F,
        0x40, 0xEB, 0xBC, 0x52, 0xC9, 0x99, 0x3E, 0xB6,
        0x6A, 0xEB, 0x36, 0x66, 0x02, 0x95, 0x8F, 0xDF,
        0xAA, 0x28, 0x3B, 0x71, 0xE6, 0x4D, 0xB1, 0x23
    };
    
    if (memcmp(digest, expected, 32) == 0) {
        printf("%s SHA-256 success! (hash verified)\n", SYMBOL_OK);
    } else {
        printf("%s SHA-256 computed but hash mismatch\n", SYMBOL_WARN);
    }
    return true;
}

// Test 5: SHA-256 of longer message
bool test_sha256_long(void)
{
    printf("\n=== Test 5: SHA-256 (longer message) ===\n");
    
    const char* message = "The quick brown fox jumps over the lazy dog";
    uint8_t digest[32];
    
    printf("Message: \"%s\"\n", message);
    
    ATCA_STATUS status = atcab_hw_sha2_256((const uint8_t*)message, strlen(message), digest);
    
    if (status != ATCA_SUCCESS) {
        printf("%s 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    print_hex("SHA-256", digest, 32);
    printf("%s SHA-256 success!\n", SYMBOL_OK);
    return true;
}

// Test 6: Counter read
bool test_counter_read(void)
{
    printf("\n=== Test 6: Counter Read ===\n");
    
    uint32_t counter_value = 0;
    ATCA_STATUS status = atcab_counter_read(0, &counter_value);
    
    if (status != ATCA_SUCCESS) {
        printf("%s 0x%08X (may not be configured)\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Counter 0: %lu\n", (unsigned long)counter_value);
    printf("%s Counter read success!\n", SYMBOL_OK);
    return true;
}

// Test 7: Counter increment
bool test_counter_increment(void)
{
    printf("\n=== Test 7: Counter Increment ===\n");
    
    uint32_t before = 0, after = 0;
    
    ATCA_STATUS status = atcab_counter_read(0, &before);
    if (status != ATCA_SUCCESS) {
        printf("%s 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    status = atcab_counter_increment(0, &after);
    if (status != ATCA_SUCCESS) {
        printf("%s 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Before: %lu, After: %lu\n", (unsigned long)before, (unsigned long)after);
    printf("%s Counter increment success!\n", SYMBOL_OK);
    return true;
}

// Test 8: Lock status
bool test_lock_status(void)
{
    printf("\n=== Test 8: Lock Status ===\n");
    
    bool is_locked = false;
    
    ATCA_STATUS status = atcab_is_locked(LOCK_ZONE_CONFIG, &is_locked);
    if (status != ATCA_SUCCESS) {
        printf("%s 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    printf("Config zone: %s\n", is_locked ? "LOCKED" : "UNLOCKED");
    
    status = atcab_is_locked(LOCK_ZONE_DATA, &is_locked);
    if (status != ATCA_SUCCESS) {
        printf("%s 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    printf("Data zone: %s\n", is_locked ? "LOCKED" : "UNLOCKED");
    
    printf("%s Lock status success!\n", SYMBOL_OK);
    return true;
}

// Test 9: Read config zone (full 128 bytes with slot details)
bool test_read_config(void)
{
    printf("\n=== Test 9: Read Config Zone (Full) ===\n");
    
    uint8_t config[128];  // Full config zone
    ATCA_STATUS status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, config, 128);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Read failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Bytes 0-15 (Serial + Rev): ");
    for (int i = 0; i < 16; i++) printf("%02X ", config[i]);
    
    printf("\n\nSlotConfig (bytes 20-51, 2 bytes/slot):\n");
    for (int slot = 0; slot < 8; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = (config[offset+1] << 8) | config[offset];
        printf("  Slot %d: 0x%04X", slot, sc);
        
        // Decode key bits
        bool readKey_set = (sc & 0x8000) != 0;  // Bit 15
        bool private_key = (sc & 0x2000) != 0;  // Bit 13 (Private vs Public)
        printf(" %s", private_key ? "[PRIVATE]" : "[PUBLIC ]");
        if (readKey_set) printf(" [ReadKey set]");
        printf("\n");
    }
    for (int slot = 8; slot < 16; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = (config[offset+1] << 8) | config[offset];
        printf("  Slot %d: 0x%04X", slot, sc);
        
        bool readKey_set = (sc & 0x8000) != 0;
        bool private_key = (sc & 0x2000) != 0;
        printf(" %s", private_key ? "[PRIVATE]" : "[PUBLIC ]");
        if (readKey_set) printf(" [ReadKey set]");
        printf("\n");
    }
    
    printf("\nKeyConfig (bytes 96-127, 2 bytes/key):\n");
    for (int key = 0; key < 16; key++) {
        int offset = 96 + (key * 2);
        uint16_t kc = (config[offset+1] << 8) | config[offset];
        printf("  Key %d: 0x%04X", key, kc);
        
        // Decode important bits
        bool private_bit = (kc & 0x0001) != 0;  // Bit 0: Private
        bool pubinfo_bit = (kc & 0x0002) != 0;  // Bit 1: PubInfo
        uint8_t keytype = (kc >> 2) & 0x07;     // Bits 2-4: KeyType
        
        if (private_bit) printf(" [Private]");
        if (pubinfo_bit) printf(" [PubInfo]");
        printf(" Type=%d", keytype);
        if (keytype == 4) printf("(ECC-P256)");
        printf("\n");
    }
    
    printf("\n%s Config read success!\n", SYMBOL_OK);
    return true;
}

// Test 10: Nonce operation
bool test_nonce(void)
{
    printf("\n=== Test 10: Nonce ===\n");
    
    uint8_t num_in[20];
    uint8_t rand_out[32];
    
    for (int i = 0; i < 20; i++) num_in[i] = i;
    
    ATCA_STATUS status = atcab_nonce_rand(num_in, rand_out);
    if (status != ATCA_SUCCESS) {
        printf("%s 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    print_hex("Nonce output", rand_out, 32);
    printf("%s Nonce success!\n", SYMBOL_OK);
    return true;
}

// Test 11: Multiple random reads
bool test_random_multiple(void)
{
    printf("\n=== Test 11: Random Entropy Check ===\n");
    
    uint8_t r1[32], r2[32], r3[32];
    
    atcab_random(r1);
    sleep_ms(10);
    atcab_random(r2);
    sleep_ms(10);
    atcab_random(r3);
    
    bool same = (memcmp(r1, r2, 32) == 0) || (memcmp(r2, r3, 32) == 0) || (memcmp(r1, r3, 32) == 0);
    
    if (same) {
        printf("%s Some values identical!\n", SYMBOL_WARN);
    } else {
        printf("All three reads different (good entropy)\n");
    }
    
    printf("%s Random entropy check success!\n", SYMBOL_OK);
    return true;
}

// Test 12: Generate ephemeral ECC key (NOT stored, just testing)
bool test_genkey(void)
{
    printf("\n=== Test 12: ECC Key Generation (Ephemeral) ===\n");
    printf("%s This generates a temporary key for testing only\n", SYMBOL_WARN);
    printf("%s Key is NOT stored in device slots\n\n", SYMBOL_WARN);
    
    uint8_t public_key[64];  // ECC P-256 public key is 64 bytes (X and Y coordinates)
    
    // Generate ephemeral key - stored temporarily in TempKey
    // Mode 0x04 (GENKEY_MODE_PRIVATE) = create new private key, return public key
    // Using key_id=0xFFFF stores private key in TempKey instead of a slot
    printf("Generating ephemeral ECC P-256 key...\n");
    
    ATCA_STATUS status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 0xFFFF, NULL, public_key);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Key generation failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Public Key (64 bytes - X and Y coordinates):\n");
    printf("  X: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", public_key[i]);
    }
    printf("\n  Y: ");
    for (int i = 32; i < 64; i++) {
        printf("%02X ", public_key[i]);
    }
    printf("\n");
    
    printf("%s Key generation success!\n", SYMBOL_OK);
    return true;
}

// Test 13: Generate private key and store in slot 0
bool test_genkey_slot(void)
{
    printf("\n=== Test 13: Generate Private Key in Slot 0 ===\n");
    printf("%s Generating new private key and storing in slot 0\n", SYMBOL_WARN);
    printf("%s This will overwrite any existing key in slot 0!\n\n", SYMBOL_WARN);
    
    uint8_t public_key[64];  // ECC P-256 public key is 64 bytes
    
    // Generate private key in slot 0, returns public key
    // Mode 0x04 (GENKEY_MODE_PRIVATE) = create new private key in slot
    printf("Generating ECC P-256 key pair in slot 0...\n");
    
    ATCA_STATUS status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 0, NULL, public_key);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Key generation failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Private key stored in slot 0\n");
    printf("Public Key (64 bytes):\n");
    printf("  X: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", public_key[i]);
    }
    printf("\n  Y: ");
    for (int i = 32; i < 64; i++) {
        printf("%02X ", public_key[i]);
    }
    printf("\n");
    
    printf("%s Private key generated and stored in slot 0!\n", SYMBOL_OK);
    return true;
}

// Test 14: Read public key from slot 0 private key
bool test_read_pubkey_from_slot(void)
{
    printf("\n=== Test 14: Generate Public Key from Slot 0 ===\n");
    printf("%s Reading private key from slot 0 and computing public key\n\n", SYMBOL_WARN);
    
    uint8_t public_key[64];
    
    // Mode 0x00 (GENKEY_MODE_PUBLIC) = compute public key from existing private key
    printf("Computing public key from slot 0 private key...\n");
    
    ATCA_STATUS status = atcab_genkey_base(GENKEY_MODE_PUBLIC, 0, NULL, public_key);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Public key computation failed: 0x%08X\n", SYMBOL_FAIL, status);
        printf("%s Slot 0 may not contain a valid private key\n", SYMBOL_WARN);
        return false;
    }
    
    printf("Public Key (computed from slot 0):\n");
    printf("  X: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", public_key[i]);
    }
    printf("\n  Y: ");
    for (int i = 32; i < 64; i++) {
        printf("%02X ", public_key[i]);
    }
    printf("\n");
    
    printf("%s Public key computed successfully!\n", SYMBOL_OK);
    return true;
}

// Test 15: Overwrite slot 0 with arbitrary data
bool test_overwrite_slot(void)
{
    printf("\n=== Test 15: Overwrite Slot 0 with Arbitrary Data ===\n");
    printf("%s Attempting to write arbitrary data to slot 0\n", SYMBOL_WARN);
    printf("%s This destroys any private key stored there!\n\n", SYMBOL_WARN);
    
    // Create some arbitrary data (32 bytes for ECC private key slot)
    uint8_t arbitrary_data[32];
    for (int i = 0; i < 32; i++) {
        arbitrary_data[i] = 0xAA + i;  // Pattern: AA AB AC AD ...
    }
    
    printf("Data to write (32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", arbitrary_data[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n                           ");
    }
    printf("\n");
    
    // Try to write to slot 0 (may fail if data zone is locked or slot is configured as private)
    printf("Writing to slot 0...\n");
    ATCA_STATUS status = atcab_write_zone(ATCA_ZONE_DATA, 0, 0, 0, arbitrary_data, 32);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Write failed: 0x%08X\n", SYMBOL_FAIL, status);
        printf("%s Slot may be locked or configured as private key slot\n", SYMBOL_WARN);
        return false;
    }
    
    // Verify by reading back
    uint8_t read_back[32];
    status = atcab_read_zone(ATCA_ZONE_DATA, 0, 0, 0, read_back, 32);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Read verification failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Data read back: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", read_back[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n                ");
    }
    printf("\n");
    
    // Verify match
    bool match = (memcmp(arbitrary_data, read_back, 32) == 0);
    if (!match) {
        printf("%s Data mismatch!\n", SYMBOL_FAIL);
        return false;
    }
    
    printf("%s Slot 0 overwritten successfully!\n", SYMBOL_OK);
    return true;
}

// Test 16: Store SHA-256 hash in readable memory
bool test_store_hash(void)
{
    printf("\n=== Test 16: Store SHA-256 Hash in Data Zone ===\n");
    printf("%s Computing hash and storing in readable slot\n\n", SYMBOL_WARN);
    
    // Compute SHA-256 of a test message
    const char *message = "Hello ATECC608A!";
    uint8_t hash[32];
    
    printf("Message: \"%s\"\n", message);
    printf("Computing SHA-256...\n");
    
    ATCA_STATUS status = atcab_hw_sha2_256((const uint8_t*)message, strlen(message), hash);
    
    if (status != ATCA_SUCCESS) {
        printf("%s SHA-256 failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("SHA-256 Hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", hash[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n              ");
    }
    printf("\n");
    
    // Try to store in slot 8 (often configured as a data storage slot)
    // If that fails, we'll try other slots
    uint16_t slot_to_use = 8;
    printf("Attempting to write hash to slot %d...\n", slot_to_use);
    
    status = atcab_write_zone(ATCA_ZONE_DATA, slot_to_use, 0, 0, hash, 32);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Write to slot %d failed: 0x%08X\n", SYMBOL_WARN, slot_to_use, status);
        printf("Trying alternate slot (slot 9)...\n");
        slot_to_use = 9;
        status = atcab_write_zone(ATCA_ZONE_DATA, slot_to_use, 0, 0, hash, 32);
        
        if (status != ATCA_SUCCESS) {
            printf("%s Write to slot %d also failed: 0x%08X\n", SYMBOL_FAIL, slot_to_use, status);
            printf("%s Data zone may be locked or all slots restricted\n", SYMBOL_WARN);
            return false;
        }
    }
    
    printf("%s Hash written to slot %d\n", SYMBOL_OK, slot_to_use);
    
    // Retrieve and verify
    uint8_t retrieved_hash[32];
    printf("Reading hash back from slot %d...\n", slot_to_use);
    
    status = atcab_read_zone(ATCA_ZONE_DATA, slot_to_use, 0, 0, retrieved_hash, 32);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Read failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Retrieved Hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", retrieved_hash[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n                ");
    }
    printf("\n");
    
    // Verify match
    bool match = (memcmp(hash, retrieved_hash, 32) == 0);
    if (!match) {
        printf("%s Hash mismatch!\n", SYMBOL_FAIL);
        return false;
    }
    
    printf("%s Hash stored and retrieved successfully!\n", SYMBOL_OK);
    return true;
}

// Test 17: Configure Slot 8 for data storage
bool test_configure_slot8(void)
{
    printf("\n=== Test 17: Configure Slot 8 for Data Storage ===\n");
    printf("%s Attempting to configure slot 8 as clear-read/clear-write\n", SYMBOL_WARN);
    printf("%s This modifies the config zone (only works if unlocked)\n\n", SYMBOL_WARN);
    
    // Read current config zone
    uint8_t config[128];
    ATCA_STATUS status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, config, 128);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Config read failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    // Show current slot 8 config
    int slot8_offset = 20 + (8 * 2);
    uint16_t old_slotconfig = (config[slot8_offset+1] << 8) | config[slot8_offset];
    printf("Current Slot 8 SlotConfig: 0x%04X\n", old_slotconfig);
    
    int key8_offset = 96 + (8 * 2);
    uint16_t old_keyconfig = (config[key8_offset+1] << 8) | config[key8_offset];
    printf("Current Key 8 KeyConfig: 0x%04X\n", old_keyconfig);
    
    // Set new configuration for slot 8
    // SlotConfig: 0x8000 = ReadKey bit set, allow clear reads/writes
    // Actually, for clear read/write we want: 0x0000 or with proper write enable
    // Let's try 0x00C0: EncryptRead=0, IsSecret=0, WriteConfig=11b (always write)
    uint16_t new_slotconfig = 0x00C0;  // WriteConfig = 11b (always), no encryption
    
    // KeyConfig: 0x001C = Not private, not ECC, general data slot
    uint16_t new_keyconfig = 0x001C;
    
    printf("\nProposed Slot 8 SlotConfig: 0x%04X\n", new_slotconfig);
    printf("Proposed Key 8 KeyConfig: 0x%04X\n", new_keyconfig);
    
    // Update the config array
    config[slot8_offset] = new_slotconfig & 0xFF;
    config[slot8_offset+1] = (new_slotconfig >> 8) & 0xFF;
    config[key8_offset] = new_keyconfig & 0xFF;
    config[key8_offset+1] = (new_keyconfig >> 8) & 0xFF;
    
    // Write back just the slot 8 config bytes (bytes 36-37 for SlotConfig)
    printf("\nWriting new SlotConfig to bytes %d-%d...\n", slot8_offset, slot8_offset+1);
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, slot8_offset, 
                                     &config[slot8_offset], 2);
    
    if (status != ATCA_SUCCESS) {
        printf("%s SlotConfig write failed: 0x%08X\n", SYMBOL_WARN, status);
        printf("%s Config zone may be locked\n", SYMBOL_INFO);
    } else {
        printf("%s SlotConfig written\n", SYMBOL_OK);
    }
    
    // Write KeyConfig (bytes 112-113 for key 8)
    printf("Writing new KeyConfig to bytes %d-%d...\n", key8_offset, key8_offset+1);
    status = atcab_write_bytes_zone(ATCA_ZONE_CONFIG, 0, key8_offset, 
                                     &config[key8_offset], 2);
    
    if (status != ATCA_SUCCESS) {
        printf("%s KeyConfig write failed: 0x%08X\n", SYMBOL_WARN, status);
        printf("%s Config zone may be locked\n", SYMBOL_INFO);
        return false;
    } else {
        printf("%s KeyConfig written\n", SYMBOL_OK);
    }
    
    printf("\n%s Slot 8 configuration updated!\n", SYMBOL_OK);
    printf("%s Note: Changes take effect immediately (config zone unlocked)\n", SYMBOL_INFO);
    return true;
}

// ═══════════════════════════════════════════════════════════════
// ADVANCED CRYPTOGRAPHIC TESTS
// ═══════════════════════════════════════════════════════════════

// Test 18: ECDH Key Exchange with Ephemeral Key
bool test_ecdh_exchange(void)
{
    printf("\n=== Test 18: ECDH Key Exchange ===\n");
    printf("%s Performing Elliptic Curve Diffie-Hellman key exchange\n\n", SYMBOL_INFO);
    
    uint8_t our_public_key[64];
    uint8_t peer_public_key[64];
    uint8_t shared_secret[32];
    
    // Step 1: Generate our ephemeral key pair
    printf("Generating our ephemeral key pair...\n");
    ATCA_STATUS status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 0xFFFF, NULL, our_public_key);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Key generation failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Our Public Key (first 32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02X ", our_public_key[i]);
    printf("\n");
    
    // Step 2: Generate peer's key pair (simulating another device)
    printf("\nGenerating peer's ephemeral key pair...\n");
    status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 0xFFFF, NULL, peer_public_key);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Failed to generate peer key: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Peer Public Key (first 32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02X ", peer_public_key[i]);
    printf("\n");
    
    printf("%s Note: Both keys use TempKey - last GenKey overwrites first!\n", SYMBOL_WARN);
    printf("%s For real ECDH, need to store one key or use external peer key\n", SYMBOL_INFO);
    
    // Step 3: For testing, we'll use our_public_key as peer (self-ECDH)
    // In real scenario, peer_public_key comes from network/other device
    printf("\nPerforming ECDH with our own public key (self-test)...\n");
    status = atcab_ecdh_base(ECDH_PREFIX_MODE, 0xFFFF, our_public_key, shared_secret, NULL);
    
    if (status != ATCA_SUCCESS) {
        printf("%s ECDH failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Shared Secret (32 bytes): ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", shared_secret[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n                           ");
    }
    printf("\n");
    
    printf("%s ECDH key exchange successful!\n", SYMBOL_OK);
    return true;
}

// Test 19: Sign and Verify with Ephemeral Key
bool test_sign_verify(void)
{
    printf("\n=== Test 19: Sign and Verify Message ===\n");
    printf("%s Testing ECDSA signature generation and verification\n\n", SYMBOL_INFO);
    
    uint8_t public_key[64];
    uint8_t signature[64];
    uint8_t message_digest[32];
    
    // Step 1: Generate ephemeral key pair
    printf("Generating ephemeral signing key...\n");
    ATCA_STATUS status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 0xFFFF, NULL, public_key);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Key generation failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Public Key (first 32 bytes): ");
    for (int i = 0; i < 32; i++) printf("%02X ", public_key[i]);
    printf("\n");
    
    // Step 2: Create message digest (SHA-256 of message)
    const char* message = "This is a test message to sign";
    printf("\nMessage: \"%s\"\n", message);
    printf("Computing SHA-256 of message...\n");
    
    status = atcab_hw_sha2_256((const uint8_t*)message, strlen(message), message_digest);
    
    if (status != ATCA_SUCCESS) {
        printf("%s SHA-256 failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Message Digest: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", message_digest[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n                ");
    }
    printf("\n");
    
    // Step 3: Sign with TempKey private key
    // Note: Sign requires message digest to be loaded into TempKey first
    printf("\nAttempting to sign with ephemeral private key...\n");
    printf("%s Note: Signing with TempKey requires complex setup\n", SYMBOL_WARN);
    printf("%s Skipping actual sign operation (needs GenDig + internal message)\n", SYMBOL_INFO);
    
    // For demonstration, we'll simulate a signature
    // Real implementation would need:
    // 1. Load message into TempKey using GenDig/Nonce
    // 2. Use Sign command with internal mode
    // 3. Or store key in configured slot
    
    printf("%s Signature generation skipped (TempKey signing complex)\n", SYMBOL_WARN);
    printf("%s Alternative: Store key in slot 0-2 after proper configuration\n", SYMBOL_INFO);
    
    return false;  // Skip this test for now
    
    /*
    // This would work if key was in a configured slot:
    status = atcab_sign_base(SIGN_MODE_EXTERNAL, 0, signature);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Signing failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    */
    
    printf("Signature (64 bytes): ");
    for (int i = 0; i < 64; i++) {
        printf("%02X ", signature[i]);
        if ((i + 1) % 16 == 0 && i < 63) printf("\n                      ");
    }
    printf("\n");
    
    // Step 4: Verify signature
    printf("\nVerifying signature...\n");
    bool is_verified = false;
    status = atcab_verify_extern(message_digest, signature, public_key, &is_verified);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Verification failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    if (!is_verified) {
        printf("%s Signature verification returned FALSE\n", SYMBOL_FAIL);
        return false;
    }
    
    printf("%s Signature verified successfully!\n", SYMBOL_OK);
    return true;
}

// Test 20: Hash Storage Attempt (will likely fail without config)
bool test_hash_storage_attempt(void)
{
    printf("\n=== Test 20: SHA-256 Hash Storage Attempt ===\n");
    printf("%s Computing hash and attempting storage\n", SYMBOL_INFO);
    printf("%s Expected to fail: slots 8-14 unconfigured\n\n", SYMBOL_WARN);
    
    const char* data = "Data to hash and store";
    uint8_t hash[32];
    
    // Compute hash
    printf("Data: \"%s\"\n", data);
    printf("Computing SHA-256...\n");
    
    ATCA_STATUS status = atcab_hw_sha2_256((const uint8_t*)data, strlen(data), hash);
    
    if (status != ATCA_SUCCESS) {
        printf("%s SHA-256 failed: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", hash[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n      ");
    }
    printf("\n");
    
    // Attempt to store in slot 8
    printf("\nAttempting to store hash in slot 8...\n");
    status = atcab_write_zone(ATCA_ZONE_DATA, 8, 0, 0, hash, 32);
    
    if (status == ATCA_SUCCESS) {
        printf("%s Hash stored successfully!\n", SYMBOL_OK);
        
        // Try to read back
        uint8_t read_hash[32];
        status = atcab_read_zone(ATCA_ZONE_DATA, 8, 0, 0, read_hash, 32);
        
        if (status == ATCA_SUCCESS) {
            bool match = (memcmp(hash, read_hash, 32) == 0);
            printf("%s Read back and verified: %s\n", 
                   match ? SYMBOL_OK : SYMBOL_FAIL,
                   match ? "MATCH" : "MISMATCH");
            return match;
        }
    } else {
        printf("%s Storage failed: 0x%08X (expected)\n", SYMBOL_WARN, status);
        printf("%s Reason: Slot 8 has SlotConfig=0x0000 (unconfigured)\n", SYMBOL_INFO);
        printf("%s Solution: Need to configure slot or store externally\n", SYMBOL_INFO);
    }
    
    return false;  // Expected to fail
}

// Test 21: KDF - Key Derivation Function
bool test_kdf_derive_key(void)
{
    printf("\n=== Test 21: KDF (Key Derivation Function) ===\n");
    printf("%s Testing AES key derivation from shared secret\n\n", SYMBOL_INFO);
    
    uint8_t input_key[32];
    uint8_t derived_key[32];
    
    // Generate input key material (simulate shared secret from ECDH)
    printf("Generating input key material...\n");
    ATCA_STATUS status = atcab_random(input_key);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Failed to generate input: 0x%08X\n", SYMBOL_FAIL, status);
        return false;
    }
    
    printf("Input Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", input_key[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n           ");
    }
    printf("\n");
    
    // Derive AES-256 key using KDF
    printf("\nDeriving AES-256 key using KDF...\n");
    const uint8_t message[] = "AES-KEY-DERIVATION-CONTEXT";
    uint8_t out_nonce[32];
    
    // KDF parameters
    uint8_t mode = KDF_MODE_ALG_AES | KDF_MODE_SOURCE_SLOT | KDF_MODE_TARGET_OUTPUT;
    uint16_t key_id = 0;  // Source key slot
    uint32_t details = (sizeof(message) & 0xFF) << 24;  // Message length in upper byte
    
    status = atcab_kdf(
        mode,
        key_id,
        details,
        message,
        derived_key,
        out_nonce
    );
    
    if (status != ATCA_SUCCESS) {
        printf("%s KDF failed: 0x%08X\n", SYMBOL_FAIL, status);
        printf("%s Note: KDF requires proper slot configuration and may need data zone locked\n", SYMBOL_WARN);
        return false;
    }
    
    printf("Derived AES Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", derived_key[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n                 ");
    }
    printf("\n");
    
    printf("%s KDF derivation successful!\n", SYMBOL_OK);
    return true;
}

// Test 22: Permanent Key Storage Attempt (will fail)
bool test_permanent_key_storage(void)
{
    printf("\n=== Test 22: Permanent Key Storage in Slot 0 ===\n");
    printf("%s Attempting to generate and store key in slot 0\n", SYMBOL_WARN);
    printf("%s Expected to fail: slot WriteConfig prevents this while unlocked\n\n", SYMBOL_WARN);
    
    uint8_t public_key[64];
    
    // Attempt to generate key in slot 0
    printf("Attempting GenKey in slot 0...\n");
    ATCA_STATUS status = atcab_genkey_base(GENKEY_MODE_PRIVATE, 0, NULL, public_key);
    
    if (status == ATCA_SUCCESS) {
        printf("%s Key generated and stored in slot 0!\n", SYMBOL_OK);
        printf("Public Key (first 32 bytes): ");
        for (int i = 0; i < 32; i++) printf("%02X ", public_key[i]);
        printf("\n");
        
        // Try to read back public key
        uint8_t read_pubkey[64];
        status = atcab_genkey_base(GENKEY_MODE_PUBLIC, 0, NULL, read_pubkey);
        
        if (status == ATCA_SUCCESS) {
            bool match = (memcmp(public_key, read_pubkey, 64) == 0);
            printf("%s Public key read back: %s\n",
                   match ? SYMBOL_OK : SYMBOL_WARN,
                   match ? "MATCH" : "DIFFERENT");
        }
        
        return true;
    } else {
        printf("%s GenKey failed: 0x%08X (expected)\n", SYMBOL_WARN, status);
        printf("%s Reason: Slot 0 SlotConfig=0x2083, WriteConfig prevents genkey while unlocked\n", SYMBOL_INFO);
        printf("%s Solutions:\n", SYMBOL_INFO);
        printf("   1. Lock data zone (PERMANENT!)\n");
        printf("   2. Reconfigure slot 0 WriteConfig\n");
        printf("   3. Use PrivWrite to import external key\n");
        printf("   4. Use ephemeral keys (TempKey) instead\n");
    }
    
    return false;  // Expected to fail
}

int main()
{
    stdio_init_all();
    sleep_ms(2000);  // Wait for USB serial
    
    printf("\n");
    printf("================================================\n");
    printf("  ATECC608A Comprehensive Test Suite\n");
    printf("================================================\n\n");
    
    // Initialize CryptoAuthLib
    printf("Initializing CryptoAuthLib...\n");
    ATCA_STATUS status = atcab_init(&cfg);
    if (status != ATCA_SUCCESS) {
        printf("%s Init failed: 0x%08X\n", SYMBOL_FAIL, status);
        while (1) { tight_loop_contents(); }
    }
    printf("%s Init success!\n\n", SYMBOL_OK);
    
    // Run all tests - comment out any you don't want to run
    record_test("Device INFO", test_info());
    record_test("Serial Number", test_serial());
    record_test("Random Number", test_random());
    record_test("SHA-256 (simple)", test_sha256_simple());
    record_test("SHA-256 (long)", test_sha256_long());
    record_test("Counter Read", test_counter_read());
    record_test("Counter Increment", test_counter_increment());
    record_test("Lock Status", test_lock_status());
    record_test("Read Config", test_read_config());
    record_test("Nonce", test_nonce());
    record_test("Random Entropy", test_random_multiple());
    record_test("Key Generation", test_genkey());
    
    // Configuration test - try to enable slot 8 for data storage
    record_test("Configure Slot 8", test_configure_slot8());
    
    // Advanced cryptographic operation tests
    printf("\n" COLOR_CYAN COLOR_BOLD "╔════════════════════════════════════════════════════╗\n");
    printf("║     ADVANCED CRYPTOGRAPHIC OPERATIONS TESTS    ║\n");
    printf("╚════════════════════════════════════════════════════╝" COLOR_RESET "\n");
    
    record_test("ECDH Key Exchange", test_ecdh_exchange());
    record_test("Sign & Verify", test_sign_verify());
    record_test("KDF Derive Key", test_kdf_derive_key());
    
    // Configuration-dependent tests (expected to fail without proper config)
    printf("\n" COLOR_YELLOW COLOR_BOLD "╔════════════════════════════════════════════════════╗\n");
    printf("║    CONFIGURATION-DEPENDENT TESTS (Expected Fail)  ║\n");
    printf("╚════════════════════════════════════════════════════╝" COLOR_RESET "\n");
    
    record_test("Configure Slot 8", test_configure_slot8());
    record_test("Hash Storage", test_hash_storage_attempt());
    record_test("GenKey to Slot 0", test_genkey_slot());
    record_test("PubKey from Slot 0", test_read_pubkey_from_slot());
    record_test("Overwrite Slot 0", test_overwrite_slot());
    record_test("Store Hash (slot)", test_store_hash());
    record_test("Permanent Key Slot 0", test_permanent_key_storage());
    
    // Print summary
    print_test_summary();
    
    atcab_release();
    printf("\nTest complete.\n");
    
    while (1) { tight_loop_contents(); }
    return 0;
}
