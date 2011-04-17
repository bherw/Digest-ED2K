use common::sense;
use Test::More tests => 11;
use constant CHUNK_SIZE => 9728000;

use Digest::ED2K qw(ed2k ed2k_hex ed2k_base64);

ok __PACKAGE__->can('ed2k_hex'), 'Exports correctly';
my $d = Digest::ED2K->new;
ok $d, 'Instance creation works';

# Tests digests.
# Assumes hexdigest and and b64digest are ok since they're inherited from Digest::base.
$d = Digest::ED2K->new->add('aaa')->hexdigest;
is $d, '918d7099b77c7a06634c62ccaf5ebac7', 'Subchunk string is correct';

# Test the tricky CHUNK_SIZE multiples.
# http://wiki.anidb.net/w/Ed2k-hash#How_is_an_ed2k_hash_calculated_exactly.3F
my $zero_chunk = Digest::ED2K->new->add("\x00" x CHUNK_SIZE)->hexdigest;
isnt $zero_chunk, 'd7def262a127cd79096a108e7a9fc138', 'The blue method is not in use for ==CHUNK_SIZE';
is $zero_chunk, 'fc21d9af828f92a8df64beac3357425d', 'The red method is in use for ==CHUNK_SIZE';

my $zero_2chunk = Digest::ED2K->new->add("\x00" x (CHUNK_SIZE * 2))->hexdigest;
isnt $zero_2chunk, '194ee9e4fa79b2ee9f8829284c466051', 'The blue method is not in use for ==CHUNK_SIZE*2';
is $zero_2chunk, '114b21c63a74b6ca922291a11177dd5c', 'The red method is in use for ==CHUNK_SIZE*2';

# Test helpers
my $bin = ed2k 'abc123';
my $hex = ed2k_hex 'abc123';
my $b64 = ed2k_base64 'abc123';
is $bin, Digest::ED2K->new->add('abc123')->digest, 'ed2k digest helper works';
is $hex, Digest::ED2K->new->add('abc123')->hexdigest, 'ed2k hexdigest helper works';
is $b64, Digest::ED2K->new->add('abc123')->b64digest, 'ed2k b64digest helper works';

# Test clone
my $original = Digest::ED2K->new->add('abc123');
is $original->clone->hexdigest, $original->hexdigest, 'cloning works';
