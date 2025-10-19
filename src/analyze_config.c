/**
 * @file analyze_config.c
 * @brief ATECC608A configuration analysis tool (READ-ONLY, NO WRITES)
 * 
 * SAFETY: This tool ONLY reads the configuration. It NEVER writes anything.
 * 
 * This tool:
 * - Reads current configuration
 * - Analyzes slot settings
 * - Shows what's wrong
 * - Proposes fixes
 * - NEVER modifies the device
 * 
 * Use this BEFORE the configuration writer to verify values are correct.
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "cryptoauthlib.h"

// ═══════════════════════════════════════════════════════════════
// COLOR CODES
// ═══════════════════════════════════════════════════════════════
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_BOLD    "\033[1m"

#define INFO   COLOR_CYAN   "[INFO]" COLOR_RESET
#define WARN   COLOR_YELLOW "[WARN]" COLOR_RESET
#define OK     COLOR_GREEN  "[OK]"   COLOR_RESET
#define FAIL   COLOR_RED    "[FAIL]" COLOR_RESET

// Global interface configuration
ATCAIfaceCfg cfg = {
    .iface_type             = ATCA_I2C_IFACE,
    .devtype                = ATECC608A,
    .atcai2c.address        = 0x6A,     // 8-bit format (0x35 << 1) - NEW CHIP!
    .atcai2c.bus            = 0,
    .atcai2c.baud           = 100000,
    .wake_delay             = 1500,
    .rx_retries             = 20
};

/**
 * @brief Decode and print SlotConfig value
 */
void decode_slotconfig(uint16_t sc, int slot) {
    printf("\n  Slot %2d [0x%04X]:\n", slot, sc);
    
    if (sc == 0x0000) {
        printf("    %s UNCONFIGURED - Slot is disabled!\n", FAIL);
        return;
    }
    
    // Decode bits
    bool readKey = (sc & 0x8000) != 0;
    bool noMAC = (sc & 0x4000) != 0;
    bool limitedUse = (sc & 0x2000) != 0;
    uint8_t encryptRead = (sc >> 10) & 0x03;
    bool isSecret = (sc & 0x0200) != 0;
    uint8_t writeConfig = (sc >> 6) & 0x03;
    bool writeKey = (sc & 0x0020) != 0;
    
    printf("    ReadKey=%d, NoMAC=%d, LimitedUse=%d\n", 
           readKey, noMAC, limitedUse);
    printf("    EncryptRead=%d, IsSecret=%d\n", 
           encryptRead, isSecret);
    printf("    WriteConfig=%d (", writeConfig);
    switch(writeConfig) {
        case 0: printf("Encrypt w/GenKey only"); break;
        case 1: printf("Encrypt always"); break;
        case 2: printf("Never"); break;
        case 3: printf("Always"); break;
    }
    printf("), WriteKey=%d\n", writeKey);
    
    // Analysis
    if (writeConfig == 0) {
        printf("    %s WriteConfig=0 prevents GenKey while unlocked\n", WARN);
    } else if (writeConfig == 3) {
        printf("    %s WriteConfig=3 allows writes anytime\n", OK);
    }
}

/**
 * @brief Decode and print KeyConfig value
 */
void decode_keyconfig(uint16_t kc, int key) {
    printf("\n  Key %2d [0x%04X]:\n", key, kc);
    
    bool private_key = (kc & 0x0001) != 0;
    bool pubInfo = (kc & 0x0002) != 0;
    uint8_t keyType = (kc >> 2) & 0x07;
    bool lockable = (kc & 0x1000) != 0;
    bool reqRandom = (kc & 0x0800) != 0;
    bool reqAuth = (kc & 0x0400) != 0;
    bool authKey = (kc & 0x0200) != 0;
    bool intrusiDisable = (kc & 0x0100) != 0;
    bool x509id = (kc & 0x0040) != 0;
    
    printf("    Private=%d, PubInfo=%d, KeyType=%d", 
           private_key, pubInfo, keyType);
    
    switch(keyType) {
        case 4: printf(" (ECC P-256)"); break;
        case 6: printf(" (AES)"); break;
        case 7: printf(" (Data)"); break;
        default: printf(" (?)"); break;
    }
    printf("\n");
    
    printf("    Lockable=%d, ReqRandom=%d, ReqAuth=%d\n",
           lockable, reqRandom, reqAuth);
    printf("    AuthKey=%d, IntrusionDisable=%d, X509id=%d\n",
           authKey, intrusiDisable, x509id);
}

/**
 * @brief Analyze configuration for issues
 */
void analyze_configuration(const uint8_t* config) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════\n");
    printf("  CONFIGURATION ANALYSIS\n");
    printf("═══════════════════════════════════════════════════════" COLOR_RESET "\n");
    
    // Check lock status from config
    uint8_t lockConfig = config[87];
    uint8_t lockValue = config[86];
    
    printf("\nLock Status (from config zone):\n");
    printf("  LockConfig: 0x%02X (%s)\n", lockConfig,
           lockConfig == 0x55 ? "UNLOCKED" : "LOCKED");
    printf("  LockValue:  0x%02X (%s)\n", lockValue,
           lockValue == 0x55 ? "UNLOCKED" : "LOCKED");
    
    if (lockConfig != 0x55) {
        printf("\n%s Config zone is LOCKED - cannot modify!\n", WARN);
        printf("  Configuration is PERMANENT.\n");
        return;
    } else {
        printf("\n%s Config zone is UNLOCKED - safe to modify\n", OK);
    }
    
    printf("\n" COLOR_BOLD "SlotConfig Analysis:" COLOR_RESET);
    for (int slot = 0; slot < 16; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = (config[offset+1] << 8) | config[offset];
        decode_slotconfig(sc, slot);
    }
    
    printf("\n" COLOR_BOLD "KeyConfig Analysis:" COLOR_RESET);
    for (int key = 0; key < 16; key++) {
        int offset = 96 + (key * 2);
        uint16_t kc = (config[offset+1] << 8) | config[offset];
        decode_keyconfig(kc, key);
    }
    
    // Identify problems
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════\n");
    printf("  IDENTIFIED ISSUES\n");
    printf("═══════════════════════════════════════════════════════" COLOR_RESET "\n");
    
    bool has_issues = false;
    
    // Check slots 0-2
    for (int slot = 0; slot <= 2; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = (config[offset+1] << 8) | config[offset];
        uint8_t writeConfig = (sc >> 6) & 0x03;
        
        if (writeConfig == 0) {
            printf("\n%s Slot %d: WriteConfig=0 prevents GenKey while unlocked\n", 
                   FAIL, slot);
            printf("  Current:  0x%04X\n", sc);
            printf("  Proposed: 0x%04X (change WriteConfig to 11b)\n", 
                   (sc & ~0x00C0) | 0x00C0);
            has_issues = true;
        }
    }
    
    // Check slots 8-14
    for (int slot = 8; slot <= 14; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = (config[offset+1] << 8) | config[offset];
        
        if (sc == 0x0000) {
            printf("\n%s Slot %d: UNCONFIGURED (0x0000)\n", FAIL, slot);
            printf("  Current:  0x%04X\n", sc);
            printf("  Proposed: 0x00C0 (WriteConfig=11, clear read/write)\n");
            
            int key_offset = 96 + (slot * 2);
            uint16_t kc = (config[key_offset+1] << 8) | config[key_offset];
            printf("  Current KeyConfig:  0x%04X\n", kc);
            printf("  Proposed KeyConfig: 0x001C (Type=7 data slot)\n");
            has_issues = true;
        }
    }
    
    if (!has_issues) {
        printf("\n%s No issues found - configuration looks good!\n", OK);
    }
}

/**
 * @brief Show recommended configuration
 */
void show_recommendations(const uint8_t* current_config) {
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════\n");
    printf("  RECOMMENDED CONFIGURATION CHANGES\n");
    printf("═══════════════════════════════════════════════════════" COLOR_RESET "\n");
    
    printf("\nFor your requirements:\n");
    printf("  1. Signature and verification → Need writable ECC slots\n");
    printf("  2. ECDH key exchange → Need writable ECC slots\n");
    printf("  3. Data storage (SHA-256) → Need configured data slots\n");
    printf("  4. Non-volatile key storage → Need persistent ECC slots\n");
    
    printf("\nRecommended changes:\n");
    
    // Slots 0-2
    printf("\n" COLOR_BOLD "Slots 0-2 (ECC Private Keys):" COLOR_RESET "\n");
    for (int slot = 0; slot <= 2; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = (current_config[offset+1] << 8) | current_config[offset];
        
        // Change WriteConfig to 11
        uint16_t new_sc = (sc & ~0x00C0) | 0x00C0;
        
        printf("  Slot %d:\n", slot);
        printf("    Current SlotConfig:  0x%04X\n", sc);
        printf("    Proposed SlotConfig: 0x%04X\n", new_sc);
        printf("    Change: Set WriteConfig bits [7:6] to 11b\n");
        printf("    Effect: Allows GenKey while unlocked\n");
    }
    
    // Slots 8-13
    printf("\n" COLOR_BOLD "Slots 8-13 (Data Storage):" COLOR_RESET "\n");
    for (int slot = 8; slot <= 13; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = (current_config[offset+1] << 8) | current_config[offset];
        
        if (sc == 0x0000) {
            printf("  Slot %d:\n", slot);
            printf("    Current SlotConfig:  0x%04X (unconfigured)\n", sc);
            printf("    Proposed SlotConfig: 0x00C0\n");
            printf("    Bits: WriteConfig=11, IsSecret=0, Clear read/write\n");
            
            int key_offset = 96 + (slot * 2);
            uint16_t kc = (current_config[key_offset+1] << 8) | current_config[key_offset];
            printf("    Current KeyConfig:  0x%04X\n", kc);
            printf("    Proposed KeyConfig: 0x001C\n");
            printf("    Bits: KeyType=7 (data), Lockable=1\n");
        }
    }
    
    printf("\n" COLOR_BOLD "Safety Notes:" COLOR_RESET "\n");
    printf("  %s These changes are REVERSIBLE (config zone unlocked)\n", OK);
    printf("  %s Can be undone by writing different values\n", OK);
    printf("  %s Does NOT lock anything\n", OK);
    printf("  %s Does NOT damage hardware\n", OK);
    printf("\n  %s Only becomes permanent if you lock config zone\n", WARN);
    printf("  %s NEVER lock borrowed hardware without authorization!\n", WARN);
}

/**
 * @brief Main entry point
 */
int main(void)
{
    stdio_init_all();
    sleep_ms(2000);  // Wait for USB serial
    
    printf("\n");
    printf("════════════════════════════════════════════════════════\n");
    printf("  ATECC608A Configuration Analysis (READ-ONLY)\n");
    printf("════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("%s This tool ONLY reads configuration\n", INFO);
    printf("%s It NEVER writes or modifies the device\n", INFO);
    printf("%s 100%% SAFE to run on borrowed hardware\n", OK);
    printf("\n");
    
    // Initialize CryptoAuthLib
    printf("%s Initializing CryptoAuthLib...\n", INFO);
    ATCA_STATUS status = atcab_init(&cfg);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Init failed: 0x%08X\n", FAIL, status);
        printf("%s Check I2C connection and device address\n", INFO);
        while (1) { tight_loop_contents(); }
    }
    
    printf("%s Init success!\n", OK);
    
    // Read current configuration (READ-ONLY)
    printf("\n%s Reading current configuration...\n", INFO);
    uint8_t config[128];
    status = atcab_read_bytes_zone(ATCA_ZONE_CONFIG, 0, 0, config, 128);
    
    if (status != ATCA_SUCCESS) {
        printf("%s Failed to read config: 0x%08X\n", FAIL, status);
        atcab_release();
        while (1) { tight_loop_contents(); }
    }
    
    printf("%s Configuration read successfully\n", OK);
    
    // Display raw configuration
    printf("\n" COLOR_BOLD "Raw Configuration Zone (128 bytes):" COLOR_RESET "\n");
    for (int i = 0; i < 128; i++) {
        if (i % 16 == 0) printf("  %02X: ", i);
        printf("%02X ", config[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    
    // Analyze configuration
    analyze_configuration(config);
    
    // Show recommendations
    show_recommendations(config);
    
    // Summary
    printf("\n" COLOR_BOLD "═══════════════════════════════════════════════════════\n");
    printf("  NEXT STEPS\n");
    printf("═══════════════════════════════════════════════════════" COLOR_RESET "\n");
    
    printf("\n1. Review the analysis above carefully\n");
    printf("2. Verify proposed values match your requirements\n");
    printf("3. Check against ATECC608A datasheet if available\n");
    printf("4. If values look correct, use config writer tool\n");
    printf("5. Or manually verify each bit field\n");
    
    printf("\n%s This tool made NO changes to your device\n", OK);
    printf("%s Configuration is unchanged\n", OK);
    
    atcab_release();
    
    printf("\n%s Analysis complete - device unchanged\n", OK);
    printf("\n");
    
    while (1) { tight_loop_contents(); }
    return 0;
}
