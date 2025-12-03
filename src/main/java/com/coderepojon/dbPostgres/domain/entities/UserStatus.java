package com.coderepojon.dbPostgres.domain.entities;

public enum UserStatus {
    ACTIVE("ACTIVE"),
    INACTIVE("INACTIVE"),
    DORMANT("DORMANT"),
    SUSPENDED("SUSPENDED"),
    BLOCKED("BLOCKED");

    private final String value;

    UserStatus(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static UserStatus fromAction(String action) {
        switch (action.toLowerCase()) {
            case "activate": return ACTIVE;
            case "deactivate": return INACTIVE;
            case "dormant": return DORMANT;
            case "suspend": return SUSPENDED;
            case "block": return BLOCKED;
            default: throw new IllegalArgumentException("Invalid action: " + action);
        }
    }
}
