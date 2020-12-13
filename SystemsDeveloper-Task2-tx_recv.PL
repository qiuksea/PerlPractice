# namespace
# opening a socket, reading data and decrypt data, check OK or fail until finish, and closing the socket.
package manage_recv;

# import modules
# IO::Socket for constructing connection between client and server.
use IO::Socket;
# read file,  returns just one line
use IO::Getline;

use integer;

# $OUTPUT_AUTOFLUSH, forces a flush after every write or print on the currently selected output channel
$| = 1;

# initial values
$finished = $global::false; # global namespace false variable (assume as false)
$failed = $global::false;
$return_code = $global::return_failed;
$client = '';
$client_address = '';
$connection = undef; # no assigned value = null as java
$read_sleptime = 0;
$read_sleepinc = 1;
$accept_sleptime = 0;
$accept_sleepinc = 10;
$timed_out = $global::false;
$rand = undef;
$trans_size_len = 6;
$connect_reject_count = 0;
$rejected = $global::false;
%args=(timeout => undef);  # timeout hash

# subroutine, generate a constant random int number between 1 and 32766 each time the program is run.
sub init # generate a constant random value each time the program is run.
{
srand(); # generate a constant value each time the program is run.
$rand = int (rand 32766) + 1; # create a random int number between 1 and 32766.
}

# subroutine decrypt input string
sub decode_transaction
{
# set up variables 
my $dec_trans;
my $trans_len;
my $junk;

#remove the last trailing newline from input string: the Package "global" variable TX
chomp $global::TX; 

# call LogFile module -> subroutine log_debug(parameter) 
# log input string decrypt transaction begin
LogFile::log_debug("about to decrypt transaction..."); 
LogFile::log_debug("TX=[ $global::TX ]"); #  value TX before decryption

# call encrypt_5 module -> subroutine decrypt() to decrypte the encrypted strings and return the value
$global::TX = encrypt_5::decrypt($global::TX); 

LogFile::log_debug("decrypted transaction...");
LogFile::log_debug("TX=[ $global::TX ]"); # value TX after decryption

if ($global::TX eq '') # if decrypted data equal empty, then log error 
	{
	LogFile::log_critical("$0: call to decrypt() returned empty transaction\n");# log file when decryption return empty 
	$return_code = $global::return_tx_error; # return error 
	return $return_code; # return error code
	};

$trans_len = substr($global::TX,(length($global::TX) - $trans_size_len));# return the substring which includes the last 6 characters of the input string
$global::TX = substr($global::TX,0,(length($global::TX) - $trans_size_len));# return the rest of input string except the last 6 characters

if ($trans_len != length($global::TX)) # sth. wrong here?: $trans_len is a substring, length($global::TX) is an integer. (assume sth. not OK)
	{
	# Module LogFile->subroutine log_critical() to log transaction is not sucessful
	LogFile::log_critical("Transaction checksum error - transaction ignored\n"); 
	$return_code = $global::return_tx_error;
	return $return_code; # return error 
	}
 
$global::transaction = $global::TX; # if OK, pass variable $global::TX to $global::transaction

if  ($global::config{log_tx}) # config() OK
	{
	# Module LogFile->subroutine log_notice() to log the received TX
	LogFile::log_notice("Received TX: ".global::sanitise_transaction( $global::transaction )."\n"); 
	}

$return_code = $global::return_ok; 
return $return_code; # return OK
}

# subroutine recv - Reads data from a socket 
sub recv_transaction
{
%args = (@_); # @_ contains the parameters passed to the subroutine, which assigns to the 'timeout' hash 

init();  # call subroutine init()

$accept_sleptime = 0;
$timed_out = $global::false;
$finished = $global::false;
$failed = $global::false;

# TCP sockets are placed in a non-blocking mode.
$global::sock->blocking($global::false);

$read_sleptime = 0;

$global::client = IO::Getline->new($global::sock);

#keep looping when not time out and not finished and not caught_signal
while	(	(! $global::caught_signal)
		&&	(! $finished)
		&&	(! $timed_out)
		)
	{

	$getline_result = $global::client->getline($global::TX);# getline() return the length of line if it read a line of input string 

	if (! defined $getline_result) # if reading input has errors
		{
		LogFile::log_debug("Socket read IO error\n"); # log error
		$return_code = $global::return_network_error; # return error
		$failed = $global::true; # as failed
		$finished = $global::true; # as finished
		}
	elsif ($getline_result > 0) # if reading messge OK
		{

		decode_transaction(); # call subroutine decode_transaction() to decrypt input string

		if	( $return_code != $global::return_ok ) # if decryption failed
			{
			$failed = $global::true;# as failed 
			}
		$finished = $global::true; # as finished
		$read_sleptime = 0;
		}
	elsif (! $getline_result) # detects the operation would block, return '0E0' which is true here -> mean 'try later again'
		{
		LogFile::log_debug("EOF on socket read\n"); # could be network error
		$return_code = $global::return_network_error; # log error
		$failed = $global::true; # as falied
		$finished = $global::true; # as finished
		}
	elsif ($getline_result == 0) # encountered end of file error
		{
		LogFile::log_debug("client->getline() timed out - (slept $read_sleptime) sleeping $read_sleepinc...\n"); # log error
		if ($read_sleptime == 0)
			{
			sleep 0;
			}
		else
			{
			sleep $read_sleepinc; # sleep 1 second
			}
		$read_sleptime += $read_sleepinc;
		if ($read_sleptime < 15) {$read_sleepinc = 1}
		else {$read_sleepinc = 5};
		if ($read_sleptime > $global::config{timeout}) # exceed timeout limition 
			{
			$timed_out = $global::true; # time out true
			LogFile::log_warn("Connection timed-out after $global::config{timeout} secs\n"); # log time out
			}
		};
	}
#TCP sockets are placed in a blocking mode -> the control is not returned to the program until the operations are complete
$global::sock->blocking($global::true);

# 
if		($global::caught_signal)
		{
		$return_code = $global::return_interrupt; # interrupt error
		}
elsif	($timed_out)
		{
		$return_code = $global::return_timed_out; # time out error
		}
elsif	($connection_rejected)
		{
		$return_code = $global::return_rejected; # rejected error
		}
elsif	(! $failed)
		{
		$return_code = $global::return_ok; # return success code
		}

return $return_code; # return status
}

#end module
return 1;

