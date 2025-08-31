package com.scb.protegrity.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class JsonEncryptionService {

    private final AESEncryptionService aesEncryptionService;
    private final ObjectMapper objectMapper;

    @Value("${encryption.fields:ssn,email,creditCard,phone,password}")
    private Set<String> fieldsToEncrypt;

    public Map<String, Object> encryptSensitiveFields(Map<String, Object> data) {
        try {
            String json = objectMapper.writeValueAsString(data);
            Map<String, Object> dataMap = objectMapper.readValue(json, Map.class);

            return processMap(dataMap, true);
        } catch (JsonProcessingException e) {
            log.error("Failed to process JSON data", e);
            throw new RuntimeException("Data processing error", e);
        }
    }

    public Map<String, Object> decryptSensitiveFields(Map<String, Object> data) {
        try {
            String json = objectMapper.writeValueAsString(data);
            Map<String, Object> dataMap = objectMapper.readValue(json, Map.class);

            return processMap(dataMap, false);
        } catch (JsonProcessingException e) {
            log.error("Failed to process JSON data", e);
            throw new RuntimeException("Data processing error", e);
        }
    }

    private Map<String, Object> processMap(Map<String, Object> dataMap, boolean encrypt) {
        for (Map.Entry<String, Object> entry : dataMap.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();

            if (fieldsToEncrypt.contains(key) && value instanceof String) {
                try {
                    String processedValue;
                    if (encrypt) {
                        processedValue = aesEncryptionService.encrypt((String) value);
                        log.info("Encrypted field '{}'", key);
                    } else {
                        processedValue = aesEncryptionService.decrypt((String) value);
                        log.info("Decrypted field '{}'", key);
                    }
                    dataMap.put(key, processedValue);
                } catch (Exception e) {
                    log.warn("Failed to {} field '{}': {}", encrypt ? "encrypt" : "decrypt", key, e.getMessage());
                }
            } else if (value instanceof Map) {
                processMap((Map<String, Object>) value, encrypt);
            }
        }
        return dataMap;
    }

    public Set<String> getFieldsToEncrypt() {
        return new HashSet<>(fieldsToEncrypt);
    }
}
