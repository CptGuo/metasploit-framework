# -*- coding: binary -*-


module Msf

###
#
# Basic block_api stubs for Windows ARCH_X86 payloads
#
###
module Payload::Windows::BlockApi

  @block_api_iv = nil

  def block_api_iv(opts={})
    if opts.key?(:block_api_iv) && !@block_api_iv.nil? && @block_api_iv != opts[:block_api_iv]
      print_warning("Warning: block_api_iv is already set to a different value, if you are using an hardcoded value, make sure to call the first function between block_api_iv, asm_block_api and block_api_hash with opts[:block_api_iv] set")
    end
    @block_api_iv ||= opts.fetch(:block_api_iv) { rand(0x100000000) }
    vprint_status("Current block_api_iv: 0x%08x" % @block_api_iv)
    @block_api_iv
  end

  def asm_block_api(opts={})
    asm = Rex::Payloads::Shuffle.from_graphml_file(
      File.join(Msf::Config.install_root, 'data', 'shellcode', 'block_api.x86.graphml'),
      arch: ARCH_X86,
      name: 'api_call'
    )
    # Patch the assembly to set the correct IV
    # db 0xbf, 0x00, 0x00, 0x00, 0x00  =>  mov edi, <iv>
    iv_bytes = [block_api_iv(opts)].pack('V').bytes.map { |b| "0x%02x" % b }.join(', ')
    asm.sub!("db 0xbf, 0x00, 0x00, 0x00, 0x00", "db 0xbf, #{iv_bytes}")
    unless asm.include?("db 0xbf, #{iv_bytes}")
      raise "Failed to patch block_api assembly with IV #{block_api_iv(opts)} (#{iv_bytes})"
    end
    asm
  end

  def block_api_hash(mod, func, opts={})
    Rex::Text.block_api_hash(mod, func, iv: block_api_iv(opts))
  end

end
end
