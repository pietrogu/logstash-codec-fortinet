# encoding: utf-8
require "logstash/util/charset"
require "logstash/codecs/base"

class LogStash::Codecs::Fortinet < LogStash::Codecs::Base
  config_name "fortinet"
  
  # Regexp per individuare le coppie key-value nel messaggio
  KEY_PATTERN = /(?:\w+(?:\.[^\s]\w+[^\|\s\.\=\\]+)?(?==))/
  VALUE_PATTERN = /(?:\S|\s++(?!#{KEY_PATTERN}=))*/
  KEY_VALUE_SCANNER = /(#{KEY_PATTERN})=(#{VALUE_PATTERN})\s*/
  
  # Regexp per trovare nelle key sintassi simile a quella di un array
  KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)$/
  # Regexp per trovare nei value degli escape character (backslash e uguale) 
  VALUE_ESCAPE_CAPTURE = /\\([\\=])/
  
  public
  def initialize(params={})
    super(params)
    # Input deve essere codificato in UTF-8
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger
  end
   
  # Con il seguent metodo effettuiamo il parsing
  def decode(data, &block)
    # Creiamo l'evento
    event = LogStash::Event.new
    # Usiamo per il log la codifica UTF-8
    @utf8_charset.convert(data)
    # Se l'encoding non ha avuto successo non andiamo avanti nel parsing, perchè nascerebbero errori
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Nel caso ci siano caratteri a delimitare l'inizio e alla fine del log, vengono rimossi
    if data[0] == "\""
      data = data[1..-2]
    end
    
    # Il log da parsare viene inserito in una variabile dal nome message
    message = data

    # Se la variabile messagge contiene degli uguali procediamo con il parsing
    if message && message.include?('=')
      # strip permette di eliminare eventuali caratteri di spazio alla fine e all'inizio
      message = message.strip
      # Ricaviamo le diverse coppie key/value del messaggio
      message.scan(KEY_VALUE_SCANNER) do |field_key, raw_field_value|
        # Con il seguente comando evitiamo che campi con sintassi simile a quella di un array possano creare errori
        field_key = field_key.sub(KEY_ARRAY_CAPTURE, '[\1]\2') if field_key.end_with?(']')
        # Gestiamo la presenza di escape sequence e dei doppi apici
        field_value = raw_field_value.gsub(VALUE_ESCAPE_CAPTURE, '\1').gsub(/["]/,'')
        # A questo punto nell'evento settiamo la coppia key-value trovata
        event.set(field_key, field_value)
      end
    end

    # Aggiungiamo il log non parsato
    event.set("RAW_MESSAGE", data.gsub(/["]/,''))

    # Portiamo in uscita l'evento
    yield event

    # In caso di errore viene mostrato il seguente messaggio
    rescue => e
      @logger.error("Failed to decode Fortinet payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
      yield LogStash::Event.new("message" => data, "tags" => ["_Fortinetparsefailure"])
    end
end
