package com.scb.protegrity.dto;

import lombok.Data;
import java.util.Map;

@Data
public class EncryptionRequest {
    private Map<String, Object> data;
}