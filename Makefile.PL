use inc::Module::Install;

name     'IO-Stream-Crypt-RC4';
all_from 'lib/IO/Stream/Crypt/RC4.pm';
author   'Alex Efros <powerman-asdf@ya.ru>';
license  'perl';

requires	'version';
requires	'Crypt::RC4';
requires	'IO::Stream';

test_requires	'Test::More';
test_requires	'Test::Exception';
test_requires	'EV';

recommends      'Test::CheckManifest'   => '0.9';
recommends      'Test::Perl::Critic';
recommends      'Test::Pod::Coverage'   => '1.08';
recommends      'Pod::Coverage'         => '0.18';
recommends      'Test::Pod'             => '1.22';

auto_install;

WriteAll;

