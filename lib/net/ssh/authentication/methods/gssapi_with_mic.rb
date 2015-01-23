require 'net/ssh/authentication/methods/abstract'
require 'net/ssh/kerberos/constants'
require 'gssapi'

module GSSAPI
  module LibGSSAPI
    # OM_uint32 gss_verify_mic (OM_uint32          *minor_status,const gss_ctx_id_t context_handle, const gss_buffer_t message_buffer,const gss_buffer_t token_buffer, gss_qop_t          qop_state)
    attach_function :gss_verify_mic, [:pointer, :pointer, :pointer, :pointer, :OM_uint32], :OM_uint32
  end
end

module Net
  module SSH
    module Authentication
      module Methods

        # Implements the Kerberos 5 SSH authentication method.
        class GssapiWithMic < Abstract
          include Net::SSH::Kerberos::Constants
          
          # Attempts to perform gssapi-with-mic Kerberos authentication
          def authenticate(next_service, username, password=nil)
              gss = nil
            
            # Try to start gssapi-with-mic authentication.
	          debug { "trying kerberos authentication" }
	          req = userauth_request(username, next_service, "gssapi-with-mic")
	          req.write_long(1)
	          supported_oid = (6.chr + GSS_KRB5_MECH.length.chr + GSS_KRB5_MECH).force_encoding(Encoding::ASCII_8BIT)
	          req.write_string(supported_oid)
	          send_message req
	          message = session.next_message
	          case message.type
	            when USERAUTH_GSSAPI_RESPONSE
	              debug { "gssapi-with-mic proceeding" }
	            when USERAUTH_FAILURE
	              info { "gssapi-with-mic failed (USERAUTH_FAILURE)" }
	              return false
	            else
	              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
	          end
	          
	          # Try to match the OID.
	          oid = message.read_string.force_encoding(Encoding::ASCII_8BIT)
	          if oid != supported_oid
              info { "gssapi-with-mic failed (USERAUTH_GSSAPI_RESPONSE)" }
              return false
	          end
	          
            options = {}
	          # Try to complete the handshake
	          gss = GSSAPI::Simple.new hostname
            if delegated_credentials = session.options[:gss_delegated_credentials]
              debug { "delegating gss credentials" }
              debug { "delegated_credentials: #{delegated_credentials}" }
              debug { "address :#{delegated_credentials.address_of}" }
              options.merge!(:credentials => delegated_credentials)
            end

            established = false
			      debug { "gssapi-with-mic handshaking" }
	          until established
	            # :delegate => true always forwards tickets.  This may or may not be a good idea, and should really be a user-specified option.
	            token = gss.init_context(token, options.merge(:delegate => true))
	            break if token === true
	            if token && token.length > 0
					      send_message Net::SSH::Buffer.from(:byte, USERAUTH_GSSAPI_TOKEN, :string, token)
	            
	                message = session.next_message
				          case message.type
				          when USERAUTH_GSSAPI_ERROR
			              message = session.next_message
			              message.get_long
			              message.get_long
				            info { "gssapi-with-mic error (USERAUTH_GSSAPI_ERROR) (#{message.read_string})" }
				          when USERAUTH_GSSAPI_ERRTOK
			              message = session.next_message
				            info { "gssapi-with-mic error (USERAUTH_GSSAPI_ERRTOK) (#{message.read_string})" }
				          when USERAUTH_FAILURE
				            info { "gssapi-with-mic failed (USERAUTH_FAILURE)" }
				            return false
				          end
	                token = message.read_string
	              
	            end
	          end
	          
	          # Attempt the actual authentication.
			      debug { "gssapi-with-mic authenticating" }
					  mic = gss.get_mic Net::SSH::Buffer.from(:string, session_id, :byte, USERAUTH_REQUEST, :string, username, 
				                                             :string, next_service, :string, "gssapi-with-mic").to_s
            if mic.nil?
              info { "gssapi-with-mic failed (context#get_mic)" }
              return false
            end
			      send_message Net::SSH::Buffer.from(:byte, USERAUTH_GSSAPI_MIC, :string, mic)
            message = session.next_message
	          case message.type
	            when USERAUTH_SUCCESS
	              info { "gssapi-with-mic success" }
	              return true
	            when USERAUTH_FAILURE
	              info { "gssapi-with-mic partial failure (USERAUTH_FAILURE)" }
	              return false
	            else
	              raise Net::SSH::Exception, "unexpected server response to USERAUTH_REQUEST: #{message.type} (#{message.inspect})"
	          end
          end

          def self.supports_server?
            true
          end

          def server_authenticate(username,next_service,auth_method,packet,auth_logic)
            #flag = packet.read_bool
            #puts "flag:#{flag}"
            mechs = packet.read_long
            found = nil
            (0...mechs).each do |mechi|
              oid = packet.read_string.force_encoding(Encoding::ASCII_8BIT)
              if oid[0] == SSH_GSS_OIDTYPE && oid[1].ord == oid.bytesize-2
                mech = oid[2..-1]
                if mech == GSS_KRB5_MECH.force_encoding(Encoding::ASCII_8BIT)
                  found = mech
                else
                  error { "unrecognized mech:#{mech} only #{GSS_KRB5_MECH.force_encoding(Encoding::ASCII_8BIT)} supported" }
                end
              else
                error { "unepxected oid:#{oid} #{oid[0].ord} #{oid[1].ord} #{oid.bytesize}" }
              end
            end
            return false unless found

            srv = GSSAPI::Simple.new(@options[:gss_server_host], @options[:gss_server_service], @options[:gss_server_keytab])
            srv.acquire_credentials

            resp = Buffer.from(:byte,USERAUTH_GSSAPI_RESPONSE)
            supported_oid = (SSH_GSS_OIDTYPE + found.length.chr + found).force_encoding(Encoding::ASCII_8BIT)
            resp.write_string(supported_oid)
            session.send_message resp

            message = session.next_message
            case message.type
              when USERAUTH_GSSAPI_TOKEN
                debug { "USERAUTH_GSSAPI_TOKEN => feed to accept_context"}
                token = message.read_string
                otok = srv.accept_context(token)
                debug { "accept_context done sending reply "}
                session.send_message Net::SSH::Buffer.from(:byte, USERAUTH_GSSAPI_TOKEN, :string, otok)
                message = session.next_message
                case message.type
                  when USERAUTH_GSSAPI_MIC
                    buffer =  Net::SSH::Buffer.from(:string, session_id, :byte, USERAUTH_REQUEST,
                          :string, username, :string, next_service, :string, "gssapi-with-mic").to_s
                    mic = message.read_string
                    debug { "verifying mic" }
                    ok = srv.verify_mic(buffer,mic)
                    debug { "mic verified: #{ok}" }
                    delegated_credentials = srv.delegated_credentials
                    debug { "delegated credentials: #{delegated_credentials}" }
                    return ok && auth_logic.allow_kerberos?(username,srv,
                      {:next_service => next_service,
                       :auth_method => auth_method,
                       :packet => packet, :method => self})
                end

              when USERAUTH_GSSAPI_ERRTOK
            end
          end

          private

            # Returns the hostname as reported by the underlying socket.
            def hostname
              session.transport.host
            end

        end

      end
    end
  end
end
