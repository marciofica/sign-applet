

import java.awt.EventQueue;
import java.io.IOException;
import java.io.Writer;

import javax.swing.text.BadLocationException;
import javax.swing.text.JTextComponent;

public class TextComponentWriter extends Writer {
	private boolean autoScroll = true;
	private StringBuilder buffer = new StringBuilder();

	private Thread bufferThread;
	private JTextComponent textComponent;

	public TextComponentWriter(JTextComponent textComponent) {
		this.textComponent = textComponent;
		Runnable r = new Runnable() {
			@Override
			public void run() {
				try {
					while (!Thread.interrupted()) {
						writeBuffer();
						Thread.sleep(100);
					}
				} catch (InterruptedException e) {
				}
				writeBuffer();
			}
		};
		bufferThread = new Thread(r, "TextComponentWriter Thread");
		bufferThread.setDaemon(true);
		bufferThread.start();
	}

	@Override
	public void close() {
		bufferThread.interrupt();
	}

	@Override
	public void flush() {
	}

	public boolean isAutoScroll() {
		return autoScroll;
	}

	public void setAutoScroll(boolean autoScroll) {
		this.autoScroll = autoScroll;
	}

	@Override
	public synchronized void write(char[] cbuf, int off, int len) throws IOException {
		buffer.append(cbuf, off, len);
	}

	@Override
	public void write(final int b) throws IOException {
		write(new char[] { (char) b }, 0, 1);
	}

	@Override
	protected void finalize() throws Throwable {
		close();
	}

	private synchronized void writeBuffer() {
		if (buffer.length() == 0) {
			return;
		}

		final String str = buffer.toString();
		buffer = new StringBuilder();

		EventQueue.invokeLater(new Runnable() {
			@Override
			public void run() {
				if (isAutoScroll()) {
					textComponent.setCaretPosition(textComponent.getDocument().getLength());
				} else if (textComponent.getCaretPosition() == textComponent.getDocument()
				        .getLength() && textComponent.getDocument().getLength() > 0) {
					textComponent.setCaretPosition(textComponent.getDocument().getLength() - 1);
				}

				try {
					textComponent.getDocument().insertString(
					        textComponent.getDocument().getLength(), str, null);
				} catch (BadLocationException e) {
				}
			}
		});
	}
}
