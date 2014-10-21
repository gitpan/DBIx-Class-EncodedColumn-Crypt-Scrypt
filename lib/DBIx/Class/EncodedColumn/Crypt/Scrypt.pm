use strict;
use warnings;

# ABSTRACT: scrypt support for DBIx::Class::EncodedColumn
package DBIx::Class::EncodedColumn::Crypt::Scrypt;

use Encode qw(is_utf8 encode_utf8);
use Crypt::ScryptKDF 0.008 qw(scrypt_hash scrypt_hash_verify
    random_bytes);

sub make_encode_sub {
    my ($class, $col, $args) = @_;

    $args->{cost}     //= 8;
    $args->{blocksz}  //= 8;
    $args->{parallel} //= 1;
    $args->{saltsz}   //= 32;
    $args->{keysz}    //= 32;

    sub {
        my ($text) = @_;
        $text = encode_utf8($text) if is_utf8($text);
        scrypt_hash(
            $text,
            random_bytes($args->{saltsz}),
            $args->{cost},
            $args->{blocksz},
            $args->{parallel},
            $args->{keysz});
    };
}

sub make_check_sub {
    my ($class, $col) = @_;

    sub {
        my ($result, $pass) = @_;
        $pass = encode_utf8($pass) if is_utf8($pass);
        scrypt_hash_verify($pass, $result->get_column($col));
    };
}

1;

=pod

=head1 NAME

DBIx::Class::EncodedColumn::Crypt::Scrypt - scrypt support for DBIx::Class::EncodedColumn

=head1 VERSION

version 0.002

=head1 SYNOPSIS

  __PACKAGE__->add_columns(
      'password' => {
          data_type           => 'text',
          encode_column       => 1,
          encode_class        => 'Crypt::Scrypt',
          encode_args         => {
          },
          encode_check_method => 'check_password',
      }
  )

=head1 DESCRIPTION

=head1 NAME

DBIx::Class::EncodedColumn::Crypt::Scrypt

=head1 ACCEPTED ARGUMENTS

=head2 cost

CPU/memory cost, as a power of 2. Give the exponent only. Default: 8

=head2 blocksz

Block size. Defaults to 8.

=head2 parallel

Parallelization parameter. Defaults to 1.

=head2 saltsz

Length of salt in bytes. Defaults to 32.

=head2 keysz

Length of derived key in bytes. Defaults to 32.

=head1 METHODS

=head2 make_encode_sub($column_name, \%encode_args)

Returns a coderef that accepts a plaintext value and returns an
encoded value.

=head2 make_check_sub($column_name, \%encode_args)

Returns a coderef that when given the row object and a plaintext value
will return a boolean if the plaintext matches the encoded value. This
is typically used for password authentication.

=head1 SEE ALSO

L<DBIx::Class::EncodedColumn>

=head1 AUTHOR

Forest Belton (fbelton) <forest@homolo.gy>

=head1 LICENSE

Copyright (c) 2014 Forest Belton

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

=head1 AUTHOR

Forest Belton <forest@homolo.gy>

=head1 COPYRIGHT AND LICENSE

This software is Copyright (c) 2014 by Forest Belton.

This is free software, licensed under:

  The MIT (X11) License

=cut

__END__;

