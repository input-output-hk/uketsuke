defmodule Uketsuke.Error do
  defexception [:code, :message]

  def raise!(code, message), do: raise(__MODULE__, code: code, message: message)

  def require!(true, _code, _message), do: :ok
  def require!(false, code, message), do: raise!(code, message)
end
