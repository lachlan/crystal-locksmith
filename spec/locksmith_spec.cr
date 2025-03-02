require "./spec_helper"

describe Locksmith do
  it "encrypts and decrypts" do
    master_key = Base64.decode("SNTYCJM+9HHo+OU898PQqB0BmREX6Q8vPm2XAi1g5JU=")
    cipher = Locksmith::Cipher.new(master_key)
    cipher.reset!

    data = "secret message"

    encrypted_data = cipher.encrypt data
    decrypted_data = cipher.decrypt encrypted_data

    decrypted_data.should eq(data)
  end
end
