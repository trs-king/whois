#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2016 Simone Carletti <weppos@weppos.net>
#++


require 'socket'
require 'whois/errors'


module Whois
  class Server

    # The SocketHandler is the default query handler provided with the Whois library.
    # It performs the WHOIS query using a synchronous socket connection.
    class SocketHandler

      # Array of connection errors to rescue
      # and wrap into a {Whois::ConnectionError}
      RESCUABLE_CONNECTION_ERRORS = [
          SystemCallError,
          SocketError,
      ]

      # Implements the Handler interface.
      #
      # It sends the request via TCP socket, and returns the response. This method also rescues
      # common socket errors, and repackages them as Whois::ConnectionError.
      #
      # @todo *args might probably be a Hash.
      #
      # @param  query [String] the string that represents the query to send via the socket
      # @param  args [Array]
      # @return [String]
      # @raise  [Whois::ConnectionError]
      def execute(query, *args)
        socket_write_read(query, *args)
      rescue *RESCUABLE_CONNECTION_ERRORS => error
        raise ConnectionError, "#{error.class}: #{error.message}"
      end


      private

      # Executes the low-level socket communication.
      #
      # It opens the socket passing given +args+, sends the +query+ and reads the response.
      #
      # @param  query [String] the request to send to the socket
      # @param  args [Array]
      # @return [String] the answer returned by the socket
      def socket_write_read(query, *args)
        client = TCPSocket.new(*args)
        client.write("#{query}\r\n")    # I could use put(foo) and forget the \n
        client.read                     # but write/read is more symmetric than puts/read
      ensure                            # and I really want to use read instead of gets.
        client.close if client          # If != client something went wrong.
      end
    end

  end
end
