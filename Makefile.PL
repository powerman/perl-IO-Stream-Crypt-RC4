use inc::Module::Install;

name     'IO-Stream-Crypt-RC4';
all_from 'lib/IO/Stream/Crypt/RC4.pm';
author   'Alex Efros <powerman-asdf@ya.ru>';
license  'perl';

requires 'version';
requires 'Crypt::RC4';
requires 'IO::Stream';

test_requires 'Test::More';
test_requires 'Test::Exception';

WriteAll;

