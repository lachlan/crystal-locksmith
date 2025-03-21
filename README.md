# Locksmith

Crystal language shard which provides a simple process for creating and
storing encryption keys, and then encrypting and decrypting text data using
said keys from where they are stored in an encrypted key file.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     simplog:
       github: lachlan/crystal-locksmith
   ```

2. Run `shards install`

## Usage

```crystal
require "locksmith"
require "random/secure"

# generate a random master key, but for production use a pre-generated key
# safely stored stored somewhere, this master key is used to encrypt the
# key file used to store the cipher key used for data encryption and
# decryption
master_key = Random::Secure.random_bytes(32)

# create a new cipher with the master key, and on first create this will
# generate a new cipher key to use for data encryption and decryption and
# store it in a key file that is encrypted with the master key next to the
# current executable named `<executable>.key`; subsequent cipher creations
# will read the cipher key from the stored key file to allow data to be
# encrypted and decrypted across sessions using the same key
cipher = Locksmith::Cipher.new(master_key)

data = "secret message"
encrypted_data = cipher.encrypt data
decrypted_data = cipher.decrypt encrypted_data
```

## Contributing

1. Fork it (<https://github.com/lachlan/crystal-locksmith/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Contributors

- [Lachlan Dowding](https://github.com/lachlan) - creator and maintainer
