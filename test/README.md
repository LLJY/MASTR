# MASTR Token - Unit Test Suite

## Overview

Comprehensive unit testing framework for the MASTR (Mutual Attested Secure Token for Robotics) embedded system. Tests all protocol phases without requiring physical hardware.

## Quick Start

```bash
cd test
cmake -B build
cmake --build build
./build/run_tests
```

## Test Suites

### 1. Serial Layer Tests (11 tests)
Tests frame assembly/disassembly, byte stuffing, and checksums.

**Files**: [`test_serial.c`](test_serial.c:1)

**Coverage**:
- Frame construction with SOF/EOF markers
- Byte stuffing for special characters (0x7D, 0x7E, 0x7F)
- Checksum calculation and validation
- Error detection (bad checksum, wrong length)
- Frame recovery after corruption

### 2. Protocol State Machine Tests (15 tests)
Tests state transitions and message routing through the protocol phases.

**Files**: [`test_protocol.c`](test_protocol.c:1)

**Coverage**:
- Phase 1: ECDH handshake (0x20 → 0x21 → 0x22)
- Phase 2: Integrity verification (0x30 → 0x32 → 0x40)
- Runtime: Heartbeat handling
- Invalid state rejections
- Error scenarios and shutdown triggers
- Re-attestation flows

### 3. Session Management Tests (14 tests)
Tests session lifecycle, timeouts, and re-attestation triggers.

**Files**: [`test_session.c`](test_session.c:1)

**Coverage**:
- Session establishment and validation
- Timeout detection (30s default)
- Session invalidation preserves encryption
- Re-attestation key management
- Heartbeat timestamp tracking
- Halt state behavior

---

## Mock Infrastructure

### Mock Modules

#### 1. **mock_crypto.c/h** - Cryptographic Operations
Mocks ATECC608A hardware and mbedTLS functions.

**Mocked Functions**:
- `ecdh_generate_ephemeral_key()` - Deterministic test keys
- `ecdh_sign_with_permanent_key()` - Test signatures
- `ecdh_verify_signature()` - Controllable verification
- `ecdh_compute_shared_secret()` - Deterministic shared secret
- `crypto_verify_integrity_challenge()` - Configurable result
- `derive_session_key()` - Simple XOR derivation for tests

**Control Functions**:
```c
mock_crypto_reset();                     // Reset to defaults
mock_crypto_set_keys(token, host);       // Set permanent keys
mock_crypto_set_golden_hash(hash);       // Set expected hash
mock_crypto_set_signature_result(pass);  // Control verification
mock_crypto_set_integrity_result(pass);  // Control integrity check
```

#### 2. **mock_time.c/h** - Time Control
Mocks Pico SDK time functions for session timeout testing.

**Mocked Functions**:
- `time_us_64()` - Returns controllable time
- `vTaskDelay()` - No actual delay in tests
- `pdMS_TO_TICKS()` - Simple 1:1 mapping

**Control Functions**:
```c
mock_time_reset();           // Reset to time 0
mock_time_set(time_us);      // Set absolute time
mock_time_advance(delta_ms); // Advance time by delta
```

#### 3. **mock_pico_sdk.c/h** - Pico SDK Functions
Mocks USB CDC serial and stdlib functions.

**Mocked Functions**:
- `tud_cdc_write_char()` - Captures output
- `get_rand_32()` - Deterministic random
- `print_dbg()` - Suppressed output
- Serial buffer injection helpers

---

## Test Helpers

### Data Injection
```c
test_inject_rx_data(data, len);  // Inject bytes into serial.c rx_buffer
load_mock_buffer(data, len);     // Wrapper for test injection
```

### Spy Functions
```c
bool was_handler_called();       // Check if message handler ran
bool was_shutdown_signal_called(); // Check shutdown triggered
uint8_t get_last_msg_type();     // Get received message type
```

### State Management
```c
setUp();   // Called before each test (resets all state)
tearDown(); // Called after each test (cleanup)
```

---

## Current Test Results

### Result Summary
```
40 Tests
26 Passing (65%)
14 Failing (35%)
0 Ignored
```

### Known Issues

#### Issue 1: Serial Receive Tests (5 failures)
**Symptom**: `was_handler_called()` returns FALSE  
**Cause**: Conflict between mock and real `handle_validated_message()`  
**Fix**: Remove mock version, use real implementation  

#### Issue 2: ECDH State Transitions (2 failures)
**Symptom**: State stuck at 0x20/0x22 instead of advancing  
**Cause**: ECDH functions wrapped in `#ifndef UNIT_TEST`  
**Fix**: Provide test execution path or adjust guards  

#### Issue 3: Re-attestation Tests (3 failures)
**Symptom**: Functions calling unmocked ATECC operations  
**Cause**: `protocol_trigger_reattestation()` needs hardware  
**Fix**: Wrap hardware calls, allow test execution  

---

## Architecture Integration

### Code Under Test
```
src/serial.c    - Serial framing/parsing ✅ Tested
src/protocol.c  - State machine/routing  ⚠️ Partially tested  
src/crypt.c     - Crypto wrappers        🔄 Mocked (not directly tested)
```

### Test Isolation
- **No Hardware Required**: All ATECC and Pico functions mocked
- **Deterministic Results**: Fixed keys/signatures for reproducibility
- **Fast Execution**: <1 second for all 40 tests
- **CI/CD Ready**: Can run in any environment

---

## Development Workflow

### Adding New Tests

1. **Create test function** in appropriate suite file
```c
void test_my_new_feature(void) {
    // Arrange
    protocol_state.current_state = 0x20;
    
    // Act
    handle_validated_message(MY_MSG, payload, len);
    
    // Assert
    TEST_ASSERT_EQUAL_UINT8(0x21, protocol_state.current_state);
}
```

2. **Register in test_runner.c**
```c
void test_my_new_feature(void);  // Forward declaration
RUN_TEST(test_my_new_feature);   // In main()
```

3. **Rebuild and run**
```bash
cd test && cmake --build build && ./build/run_tests
```

### Debugging Failed Tests

```bash
# Run with verbose output
./build/run_tests -v

# Run specific test by modifying test_runner.c temporarily
# Comment out unwanted RUN_TEST() calls

# Check state after test
# Add printf() in test function (output goes to stdout)
```

---

## Future Enhancements

### Priority 1: Fix Failing Tests
- [ ] Resolve serial receive handler conflicts
- [ ] Fix ECDH state transition tests
- [ ] Enable re-attestation test execution

### Priority 2: Expand Coverage
- [ ] Add crypto operation tests (AES-GCM, HKDF)
- [ ] Add integration tests (complete flows)
- [ ] Test all error paths
- [ ] Add edge case tests

### Priority 3: Test Infrastructure
- [ ] Add code coverage reporting (gcov/lcov)
- [ ] Create CI/CD pipeline
- [ ] Add performance benchmarks
- [ ] Create test data generators

---

## Dependencies

- **Unity** v2.5.2 - Test framework (auto-downloaded)
- **CMake** 3.13+ - Build system
- **GCC** - C compiler

---

## Contributing

When adding new protocol features:

1. ✅ Write tests FIRST (TDD approach)
2. ✅ Update mocks if new hardware functions added
3. ✅ Ensure tests pass before merging
4. ✅ Update this README with new test descriptions

---

## License

Same as main project (see LICENSE.TXT)

---

**Last Updated**: 2025-11-01  
**Maintained By**: MASTR Development Team