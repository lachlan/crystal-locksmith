require "random/secure"
require "openssl"
require "uri"

# Creates and stores cipher keys in encrypted obfuscated file and supports
# encrypting and decrypting strings using those stored keys.
module Locksmith
  VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}

  # Methods for encrypting and decrypting data using keys stored in a key file
  class Cipher
    CIPHER_NAME          = "aes-256-cbc"
    CIPHER_MARK          = CIPHER_NAME + ";"
    KEY_FILE_START_MARK  = ("KEY:" + CIPHER_MARK).to_slice
    KEY_FILE_CIPHER_MARK = CIPHER_MARK.to_slice

    # The file where the cipher key is stored
    @filename : String
    # The master key used to encrypt the key file
    @master_key : Bytes
    # The cipher key used to encrypt and decrypt data
    @key : Bytes?

    # Creates a new *Cipher* with the given *master_key* which is required to
    # be specified as a 32-byte value, and an optional filename for where the
    # key file is stored which if not specified will be stored next to the
    # current executable as a .key file
    def initialize(@master_key : Bytes, filename : String? = nil)
      if f = filename
        @filename = f
      else
        @filename = default_filename
      end
    end

    # Deletes existing key file if it exists and then lazily generates a new
    # one when first required by next encrypt or decrypt invocation.
    # Warning: this is a destructive action and will cause the loss of any
    # existing cipher key and therefore ability to decrypt or encrypt using
    # that existing key.
    def reset! : Nil
      File.delete filename
    end

    # The filename where the cipher keys are stored
    def filename : String
      @filename
    end

    # Encrypts the given plaintext *data*
    def encrypt(data : String) : String
      encrypt(key, data)
    end

    # Decrypts the given ciphertext *data*
    def decrypt(data : String) : String
      decrypt(key, data)
    end

    # Decrypts only if data starts with "{{ CIPHER_MARK }}"
    # otherwise returns data as is
    def decrypt?(data : String?) : String?
      if (secret = data) && encrypted?(secret)
        data = decrypt secret.sub(CIPHER_MARK) { "" }
      end
      data
    end

    # Returns `true` if *data* starts with "{{ CIPHER_MARK }}"
    def encrypted?(data : String?) : Bool
      !data.nil? && data.starts_with? CIPHER_MARK
    end

    # Returns the cipher key used to encrypt and decrypt secrets
    private def key : Bytes
      @key ||= fetch_key
    end

    # Reads the cipher key from disk and returns it
    private def fetch_key : Bytes
      filename = @filename
      # ensure key file if it exists is not a directory
      raise IO::Error.new("malformed key file: #{filename}") if File.directory?(filename)

      # create newly generated key file if it doesn't already exist
      create_key_file(filename) unless File.exists?(filename)

      # read key file contents to byte array
      encrypted_contents = File.open(filename) do |file|
        file.getb_to_end
      end

      # decrypt key file contents with master key
      contents = decrypt(@master_key, encrypted_contents)
      # ensure key file header is well formed
      raise IO::Error.new("malformed key file: #{filename}") unless contents[0..(KEY_FILE_START_MARK.size - 1)] == KEY_FILE_START_MARK

      # first n bytes is the start mark, next 256 bytes is the prefix, next 32 bytes is the intermediate key used to encrypt the cipher key
      intermediate_key = contents[(256 + KEY_FILE_START_MARK.size)..(287 + KEY_FILE_START_MARK.size)]
      # remaining bytes is the encrypted cipher key and salt
      encrypted_cipher_contents = contents[(288 + KEY_FILE_START_MARK.size)..]

      # decrypt cipher key with intermediate key
      cipher_contents = decrypt(intermediate_key, encrypted_cipher_contents)
      # ensure cipher contents is well formed
      raise IO::Error.new("malformed key file: #{filename}") unless cipher_contents.size == (288 + KEY_FILE_CIPHER_MARK.size) || cipher_contents[0..(KEY_FILE_CIPHER_MARK.size - 1)] == KEY_FILE_CIPHER_MARK

      # first n bytes is the start mark, next 32 bytes is the cipher key, the remaining 256 bytes is the salt
      cipher_key = cipher_contents[KEY_FILE_CIPHER_MARK.size..(31 + KEY_FILE_CIPHER_MARK.size)]
    rescue ex : OpenSSL::Cipher::Error
      raise IO::Error.new("malformed key file: #{filename}", ex)
    end

    # Returns the filename used to store the master and cipher keys
    private def default_filename : String
      if executable_path = ::Process.executable_path
        executable_filename = File.basename executable_path
        executable_directory = File.dirname executable_path

        File.join executable_directory, "#{executable_filename.split(".").shift? || executable_filename}.key"
      else
        raise IO::Error.new("executable path not found")
      end
    end

    # Creates new intermediate and cipher keys and stores them in the key file encrypted with the master key
    private def create_key_file(filename : String) : Nil
      raise "key file must not exist: #{filename}" if File.exists?(filename)

      prefix = Random::Secure.random_bytes(256)
      cipher_key = Random::Secure.random_bytes(32)
      intermediate_key = Random::Secure.random_bytes(32)
      suffix = Random::Secure.random_bytes(256)

      File.open(filename, "w") do |file|
        file.write encrypt(@master_key, KEY_FILE_START_MARK + prefix + intermediate_key + encrypt(intermediate_key, KEY_FILE_CIPHER_MARK + cipher_key + suffix))
      end
    end

    # Encrypts the given text *data* with the given *key* returning
    # a base64-encoded string
    private def encrypt(key : Bytes, data : String) : String
      Base64.strict_encode(encrypt(key, data.to_slice))
    end

    # Decrypts the given base64-encoded encrypted *data* with
    # the given *key* returning the decrypted text
    private def decrypt(key : Bytes, data : String) : String
      String.new decrypt(key, Base64.decode(data))
    end

    # Encrypts the given *data* with the given *key* returning
    # the encrypted data
    private def encrypt(key : Bytes, data : Bytes) : Bytes
      cipher(key, data) do |c|
        c.encrypt
      end
    end

    # Decrypts the given *data* with the given *key* returning
    # the decrypted data
    private def decrypt(key : Bytes, data : Bytes) : Bytes
      cipher(key, data) do |c|
        c.decrypt
      end
    end

    # Encrypts or decrypts the given *data* with the given *key*
    # returning the result
    private def cipher(key : Bytes, data : Bytes, &) : Bytes
      cipher = OpenSSL::Cipher.new(CIPHER_NAME)

      yield cipher

      cipher.key = key

      io = IO::Memory.new
      io.write(cipher.update(data))
      io.write(cipher.final)
      io.rewind

      io.to_slice
    end
  end
end
