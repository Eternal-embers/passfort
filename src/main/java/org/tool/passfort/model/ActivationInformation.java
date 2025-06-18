package org.tool.passfort.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ActivationInformation {
    private UserVerification userVerification;
    private String verificationCode;
    private String codeKey;
}
