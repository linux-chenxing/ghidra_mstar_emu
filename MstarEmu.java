/*
 * Basic MStar/SigmaStar ARMv7 emulator
 *
 */
//@category linux-chenxing.Emulator

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

import java.util.ArrayList;
import java.util.List;


public class MstarEmu extends GhidraScript {

    static private abstract class Device {
        boolean noisy = false;
        private final long start;
        private final long end;

        protected final GhidraScript script;

        Device(GhidraScript script, long start, long end) {
            this.script = script;
            this.start = start;
            this.end = end;
        }

        public boolean acceptAccess(long offset, long size) {
            return (offset >= start && offset < end);
        }

        protected int registerOffset(long offset) {
            return (int) (offset - start);
        }

        public abstract void writeRegister(long offset, long value);

        public abstract long readRegister(long offset, boolean internal);

        public void doTick() {

        }
    }

    static private class Timer extends Device {
        static private final long TIMER_LEN = 0x40;
        static private final long TIMER_MAXL = 0x8;
        static private final long TIMER_MAXH = 0xc;
        static private final long TIMER_COUNTERL = 0x10;
        static private final long TIMER_COUNTERH = 0x14;

        static private final long TIMER0_START = 0x6040;
        static private final long TIMER0_END = TIMER0_START + TIMER_LEN;

        static private final long RESOLUTION = 100;
        private long counter = 0;

        private long max = 0xffffffffL;

        private Timer(GhidraScript script, long start, long end) {
            super(script, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {
            if (noisy)
                script.print("Timer register write\n");
        }

        @Override
        public long readRegister(long offset, boolean internal) {
            long reg = registerOffset(offset);
            if (!internal && noisy)
                script.printf("timer read %d\n", counter);
            if (reg == TIMER_MAXL)
                return max & 0xffffffff;
            else if (reg == TIMER_MAXH)
                return (max >> 16) & 0xffffffff;
            else if (reg == TIMER_COUNTERL) {
                int l = (int) (counter & 0xffff);
                return l;
            } else if (reg == TIMER_COUNTERH) {
                int h = (int) ((counter >> 16) & 0xffff);
                return h;
            } else
                return 0;
        }

        @Override
        public void doTick() {
            super.doTick();
            if (counter < max)
                counter += RESOLUTION;
        }

        static Timer timer0(GhidraScript script) {
            return new Timer(script, Timer.TIMER0_START, TIMER0_END);
        }
    }

    static private class WDT extends Device {
        private static long WDT_START = 0x6000;
        private static long WDT_END = 0x6020;

        private WDT(GhidraScript script, long start, long end) {
            super(script, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {
            long regoffset = registerOffset(offset);
            if (noisy)
                script.printf("WDT write: %x\n", regoffset);
        }

        @Override
        public long readRegister(long offset, boolean internal) {
            long regoffset = registerOffset(offset);

            if (!internal && noisy)
                script.printf("WDT read: %x\n", regoffset);
            return 0;
        }


        static WDT wdt(GhidraScript script) {
            return new WDT(script, WDT.WDT_START, WDT.WDT_END);
        }
    }

    static private class UART extends Device {

        static private final long PMUART_START = 0x221000;
        static private final long PMUART_END = PMUART_START + 0x100;

        static private final int UART_THR_RBR_DLL = 0x0;
        static private final int UART_IER_DLH = 0x8;
        static private final int UART_LCR = 0x18;
        static private final int UART_LCR_DL = (1 << 7);
        static private final int UART_LSR = 0x28;
        static private final int UART_LSR_TXEMPTY = (1 << 6);
        static private final int UART_LSR_TXFIFOEMPTY = (1 << 5);
        long lcr = 0x3L;
        long dll = 0;
        long dlh = 0;
        long ier = 0;

        StringBuffer txBuffer = new StringBuffer();

        UART(GhidraScript script, long start, long end) {
            super(script, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {
            int reg = registerOffset(offset);
            if (noisy)
                script.printf("uart write %x\n", reg);
            switch (reg) {
                case UART_THR_RBR_DLL:
                    if ((lcr & UART_LCR_DL) != 0)
                        dll = value;
                    else {
                        char c = (char) value;
                        if (c == '\n') {
                            script.printf("UART TX: %s\n", txBuffer.toString());
                            txBuffer = new StringBuffer();
                        } else
                            txBuffer.append(c);
                    }
                    break;
                case UART_IER_DLH:
                    if ((lcr & UART_LCR_DL) != 0)
                        dll = value;
                    else
                        ier = value;
                    break;
                case UART_LCR:
                    lcr = value;
                    break;
            }
        }

        @Override
        public long readRegister(long offset, boolean internal) {
            int reg = registerOffset(offset);

            if (!internal && noisy)
                script.printf("uart read %x\n", reg);
            switch (reg) {
                case UART_LCR:
                    return lcr;
                case UART_LSR:
                    // TX is always ready to go!
                    return UART_LSR_TXEMPTY | UART_LSR_TXFIFOEMPTY;
            }
            return 0;
        }

        static UART pmUart(GhidraScript script) {
            return new UART(script, PMUART_START, PMUART_END);
        }
    }

    static private class CPUPLL extends Device {

        private static final long CPUPLL_START = 0x206400;
        private static final long CPUPLL_END = CPUPLL_START + 0x200;

        CPUPLL(GhidraScript script, long start, long end) {
            super(script, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0xffff;
        }

        static CPUPLL cpupll(GhidraScript script) {
            return new CPUPLL(script, CPUPLL_START, CPUPLL_END);
        }
    }

    static private class CHIPTOP extends Device {

        static final long CHIPTOP_START = 0x203c00;
        static final long CHIPTOP_END = CHIPTOP_START + 0x200;

        static final int CHIPTOP_BOND_IN = 0x120;

        final long bondValue;

        CHIPTOP(GhidraScript script, long start, long end, long bondValue) {
            super(script, start, end);
            this.bondValue = bondValue;
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            int reg = registerOffset(offset);
            switch (reg) {
                case CHIPTOP.CHIPTOP_BOND_IN:
                    return bondValue;
                default:
                    return 0;
            }
        }

        static CHIPTOP chiptopSSD210(GhidraScript ghidraScript) {
            return new CHIPTOP(ghidraScript, CHIPTOP_START, CHIPTOP_END, 0x06);
        }
    }

    private class Bus {
        private final long start;
        private final long end;

        private final MemoryAccessFilter memoryAccessFilter;

        private final List<Device> devices = new ArrayList<>();

        boolean noisy = false;

        Bus(long start, long end) {
            this.start = start;
            this.end = end;

            memoryAccessFilter = new MemoryAccessFilter() {

                private void checkSize(int size) {
                    if (!(size == 4 || size == 2 || size == 1))
                        throw new IllegalArgumentException("Bad size");
                }

                private long getValueShift(long offset) {
                    return (offset % 4) * 8;
                }

                private long getRegisterAddress(long offset) {
                    long alignment = offset % 4;
                    return offset - alignment;
                }

                @Override
                protected void processRead(AddressSpace spc, long off, int size, byte[] values) {
                    if (!(off >= start && off < end))
                        return;

                    checkSize(size);

                    long riuOffset = off - start;
                    long registerOffset = getRegisterAddress(riuOffset);
                    long value = 0;

                    boolean handled = false;
                    for (Device d : devices) {
                        if (d.acceptAccess(riuOffset, size)) {
                            value = d.readRegister(registerOffset, false) >> getValueShift(riuOffset);
                            switch (size) {
                                case 4:
                                    longToFourByte(value, values);
                                    break;
                                case 2:
                                    longToTwoByte(value, values);
                                    break;
                                case 1:
                                    longToByte(value, values);
                                    break;
                            }
                            if (noisy)
                                printf("RIU Register read:\t0x%08x = 0x%08x\n", riuOffset, value);
                            handled = true;
                            break;
                        }
                    }
                    if (!handled)
                        printf("RIU Register unhandled read:\t0x%08x\n", riuOffset);
                }

                @Override
                protected void processWrite(AddressSpace spc, long off, int size, byte[] values) {
                    if (!(off >= start && off < end))
                        return;

                    checkSize(size);

                    long riuOffset = off - start;
                    long registerOffset = getRegisterAddress(riuOffset);


                    boolean handled = false;
                    for (Device d : devices)
                        if (d.acceptAccess(riuOffset, size)) {
                            long currentValue = d.readRegister(registerOffset, true);
                            long valueShift = getValueShift(riuOffset);
                            long newValue = currentValue;
                            switch (size) {
                                case 4:
                                    newValue = fourByteToLong(values);
                                    break;
                                case 2:
                                    newValue &= ~(0xffffL << valueShift);
                                    newValue |= (twoBytesToLong(values) << valueShift);
                                    break;
                                case 1:
                                    newValue &= ~(0xffL << valueShift);
                                    newValue |= (byteToLong(values) << valueShift);
                                    break;
                            }
                            if (noisy)
                                printf("RIU Register write:\t0x%08x: 0x%08x -> 0x%08x, write size %d\n",
                                        riuOffset, currentValue, newValue, size);
                            d.writeRegister(riuOffset, newValue);

                            handled = true;
                            break;
                        }
                    if (!handled)
                        printf("RIU Register unhandled write:\t0x%08x, write size %d\n",
                                riuOffset, size);
                }
            };
        }

        public void doTick() {
            for (Device d : devices)
                d.doTick();
        }

        public MemoryAccessFilter getMemoryAccessFilter() {
            return memoryAccessFilter;
        }

        public void registerDevice(Device device) {
            devices.add(device);
        }

    }

    private static long RIU_START = 0x1f000000;
    private static long RIU_END = 0x20000000;


    static long bytesToLong(byte[] bytes, int nbytes) {
        long value = 0;
        for (int i = 0; i < nbytes; i++)
            value |= bytes[i] << (8 * i);
        return value;
    }

    static long fourByteToLong(byte[] bytes) {
        return bytesToLong(bytes, 4);
    }

    static long twoBytesToLong(byte[] bytes) {
        return bytesToLong(bytes, 2);
    }

    static long byteToLong(byte[] bytes) {
        return bytesToLong(bytes, 1);
    }

    static void longToBytes(long val, byte[] bytes, int nbytes) {
        for (int i = 0; i < nbytes; i++)
            bytes[i] = (byte) ((val >> (8 * i)) & 0xff);
    }

    static void longToFourByte(long val, byte[] bytes) {
        longToBytes(val, bytes, 4);
    }

    static void longToTwoByte(long val, byte[] bytes) {
        longToBytes(val, bytes, 2);
    }

    static void longToByte(long val, byte[] bytes) {
        longToBytes(val, bytes, 1);
    }

    @Override
    protected void run() throws Exception {
        EmulatorHelper emulatorHelper = new EmulatorHelper(getCurrentProgram());

        final BreakCallBack dummyCallOtherCallback = new BreakCallBack() {
            boolean noisy = false;

            @Override
            public boolean pcodeCallback(PcodeOpRaw op) {
                if (noisy)
                    printf("Ignoring pcode: %s\n", op.toString());
                return true;
            }
        };
        emulatorHelper.registerDefaultCallOtherCallback(dummyCallOtherCallback);

        Bus riu = new Bus(RIU_START, RIU_END);
        riu.registerDevice(WDT.wdt(this));
        riu.registerDevice(Timer.timer0(this));
        riu.registerDevice(UART.pmUart(this));
        riu.registerDevice(CPUPLL.cpupll(this));
        riu.registerDevice(CHIPTOP.chiptopSSD210(this));

        emulatorHelper.getEmulator().addMemoryAccessFilter(riu.getMemoryAccessFilter());

        emulatorHelper.getEmulator().addMemoryAccessFilter(new MemoryAccessFilter() {
            @Override
            protected void processRead(AddressSpace spc, long off, int size, byte[] values) {
                if (off >= RIU_START && off < RIU_END) {
                    long riuoff = off - RIU_START;
                }
            }

            @Override
            protected void processWrite(AddressSpace spc, long off, int size, byte[] values) {
                if (off >= RIU_START && off < RIU_END) {
                    long riuoff = off - RIU_START;
                    if (riuoff == 200800)
                        printf("New check point 0x%08x\n", fourByteToLong(values));
                }
            }
        });

        emulatorHelper.writeRegister("pc", 0xa0000000);

        while (!monitor.isCancelled()) {
            boolean noisy = false;

            if (noisy) {
                Address a = emulatorHelper.getExecutionAddress();
                long regR0 = emulatorHelper.readRegister(currentProgram.getProgramContext()
                        .getRegister("R0")).longValue();
                long regR1 = emulatorHelper.readRegister(currentProgram.getProgramContext()
                        .getRegister("R1")).longValue();

                printf("PC: %s, R0: 0x%08x, R1: 0x%08x\n",
                        a.toString(), regR0, regR1);
            }

            if (!emulatorHelper.step(monitor)) {
                print(emulatorHelper.getLastError());
                break;
            }
            Thread.sleep(1);
            riu.doTick();
        }

        emulatorHelper.dispose();

    }
}