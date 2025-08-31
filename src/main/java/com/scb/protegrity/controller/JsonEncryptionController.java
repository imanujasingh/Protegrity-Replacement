package com.scb.protegrity.controller;



import com.scb.protegrity.dto.EncryptionRequest;
import com.scb.protegrity.service.JsonEncryptionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/json")
@RequiredArgsConstructor
@Slf4j
public class JsonEncryptionController {

    private final JsonEncryptionService jsonEncryptionService;

    @PostMapping("/encrypt")
    public ResponseEntity<Map<String, Object>> encryptJson(@RequestBody EncryptionRequest request) {
        try {
            log.info("Received encryption request for data: {}", request.getData());

            Map<String, Object> encryptedData = jsonEncryptionService.encryptSensitiveFields(request.getData());

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "JSON encrypted successfully");
            response.put("data", encryptedData);
            response.put("encryptedFields", jsonEncryptionService.getFieldsToEncrypt());

            log.info("Encryption completed successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Encryption failed", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Encryption failed: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @PostMapping("/decrypt")
    public ResponseEntity<Map<String, Object>> decryptJson(@RequestBody EncryptionRequest request) {
        try {
            log.info("Received decryption request");

            Map<String, Object> decryptedData = jsonEncryptionService.decryptSensitiveFields(request.getData());

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "JSON decrypted successfully");
            response.put("data", decryptedData);

            log.info("Decryption completed successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Decryption failed", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("status", "error");
            errorResponse.put("message", "Decryption failed: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    @GetMapping("/fields")
    public ResponseEntity<Map<String, Object>> getEncryptableFields() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("encryptableFields", jsonEncryptionService.getFieldsToEncrypt());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        return ResponseEntity.ok("✅ JSON Encryption API is running!");
    }
}
