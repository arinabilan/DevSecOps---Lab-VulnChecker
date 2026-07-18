package com.devsecops.vulncheckerbackend.dto;

public class UserRequest {
    private String firstName;
    private String paternalLastName;
    private String maternalLastName;
    private String email;
    private String password;

    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }

    public String getPaternalLastName() { return paternalLastName; }
    public void setPaternalLastName(String paternalLastName) { this.paternalLastName = paternalLastName; }

    public String getMaternalLastName() { return maternalLastName; }
    public void setMaternalLastName(String maternalLastName) { this.maternalLastName = maternalLastName; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
