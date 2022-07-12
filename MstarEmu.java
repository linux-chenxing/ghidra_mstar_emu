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
import java.util.HashMap;
import java.util.List;


public class MstarEmu extends GhidraScript {

    static private abstract class Device {
        boolean noisy = false;

        protected final String name;
        private final long start;
        private final long end;

        protected final GhidraScript script;

        Device(GhidraScript script, String name, long start, long end) {
            this.script = script;
            this.name = name;
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

        public boolean isMundane() {
            return false;
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

        private Timer(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
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
            return new Timer(script, "timer0", Timer.TIMER0_START, TIMER0_END);
        }

        @Override
        public boolean isMundane() {
            return true;
        }
    }

    static private class WDT extends Device {
        private static long WDT_START = 0x6000;
        private static long WDT_END = 0x6020;

        private WDT(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
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
            return new WDT(script, "wdt", WDT.WDT_START, WDT.WDT_END);
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

        UART(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
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
            return new UART(script, "pmuart", PMUART_START, PMUART_END);
        }

        @Override
        public boolean isMundane() {
            return true;
        }
    }

    static private class MPLL extends Device {

        static final long MPLL_START = 0x206000L;
        static final long MPLL_END = MPLL_START + 0x200L;

        MPLL(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0;
        }

        static MPLL mpll(GhidraScript script) {
            return new MPLL(script, "mpll", MPLL_START, MPLL_END);
        }
    }

    static private class MIUPLL extends Device {

        static final long MIUPLL_START = 0x206200L;
        static final long MIUPLL_END = MIUPLL_START + 0x200L;

        MIUPLL(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0;
        }

        static MIUPLL miupll(GhidraScript script) {
            return new MIUPLL(script, "miupll", MIUPLL_START, MIUPLL_END);
        }
    }

    static private class UPLL extends Device {

        static final long UPLL0_START = 0x284000L;
        static final long UPLL0_END = UPLL0_START + 0x200L;

        UPLL(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0;
        }

        static UPLL upll0(GhidraScript script) {
            return new UPLL(script, "upll0", UPLL0_START, UPLL0_END);
        }
    }

    static private class CPUPLL extends Device {

        private static final long CPUPLL_START = 0x206400;
        private static final long CPUPLL_END = CPUPLL_START + 0x200;

        CPUPLL(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0xffff;
        }

        static CPUPLL cpupll(GhidraScript script) {
            return new CPUPLL(script, "cpupll", CPUPLL_START, CPUPLL_END);
        }
    }

    static private class CLKGEN extends Device {

        private static final long CLKGEN_START = 0x207000;
        private static final long CLKGEN_END = CLKGEN_START + 0x200;

        CLKGEN(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0x0;
        }

        static CLKGEN clkgen(GhidraScript script) {
            return new CLKGEN(script, "clkgen", CLKGEN_START, CLKGEN_END);
        }
    }

    static private class PADTOP extends Device {

        private static long PADTOP_START = 0x207800L;
        private static long PADTOP_END = PADTOP_START + 0x200L;

        private PADTOP(GhidraScript script, String name) {
            super(script, name, PADTOP_START, PADTOP_END);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            // only for msc8336..
            int reg = registerOffset(offset);
            switch (reg) {
                case 0x18:
                    return 0x01L;
            }

            return 0;
        }

        static public PADTOP msc8336(GhidraScript script) {
            return new PADTOP(script, "msc8336-padtop");
        }
    }

    static private class MSC8336MYSTERY extends Device {


        MSC8336MYSTERY(GhidraScript script) {
            super(script, "msc8336mystery", 0x3c00L, 0x3c00L + 0x200L);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0xd9;
        }
    }

    static private class CHIPTOP extends Device {

        static final long CHIPTOP_START = 0x203c00;
        static final long CHIPTOP_END = CHIPTOP_START + 0x200;

        static final int CHIPTOP_BOND_IN = 0x120;

        final long bondValue;

        CHIPTOP(GhidraScript script, String name, long start, long end, long bondValue) {
            super(script, name, start, end);
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
                    if (bondValue == -1) {
                        script.printf("Reading bond value on chip that doesn't have one\n");
                        return 0;
                    } else
                        return bondValue;
                default:
                    return 0;
            }
        }

        static CHIPTOP chiptopMSC313E(GhidraScript ghidraScript) {
            return new CHIPTOP(ghidraScript, "chiptop_msc313e",
                    CHIPTOP_START, CHIPTOP_END, -1);
        }

        static CHIPTOP chiptopSSD201(GhidraScript ghidraScript) {
            return new CHIPTOP(ghidraScript, "chiptop_ssd201",
                    CHIPTOP_START, CHIPTOP_END, 0x1d);
        }

        static CHIPTOP chiptopSSD202D(GhidraScript ghidraScript) {
            return new CHIPTOP(ghidraScript, "chiptop_ssd202D",
                    CHIPTOP_START, CHIPTOP_END, 0x1e);
        }

        static CHIPTOP chiptopSSD210(GhidraScript ghidraScript) {
            return new CHIPTOP(ghidraScript, "chiptop_ssd210",
                    CHIPTOP_START, CHIPTOP_END, 0x06);
        }
    }

    static private class EFUSE extends Device {

        private static final long EFUSE_START = 0x4000;
        private static final long EFUSE_END = EFUSE_START + 0x200;

        EFUSE(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {

        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0;
        }

        static EFUSE efuse(GhidraScript script) {
            return new EFUSE(script, "efuse", EFUSE_START, EFUSE_END);
        }
    }

    static private class MAILBOX extends Device {

        private static final long MAILBOX_START = 0x200800;
        private static final long MAILBOX_END = MAILBOX_START + 0x200;

        MAILBOX(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {
            script.printf("New check point 0x%08x\n", value);
        }

        @Override
        public long readRegister(long offset, boolean internal) {
            return 0;
        }

        static MAILBOX mailbox(GhidraScript script) {
            return new MAILBOX(script, "mailbox", MAILBOX_START, MAILBOX_END);
        }
    }

    static class MIUANA extends Device {
        private static final long MIUANA_START = 0x202000;
        private static final long MIUANA_END = MIUANA_START + 0x200;

        private static final int REG_60 = 0x60;
        private static final int REG_64 = 0x64;

        private long reg60;
        private long reg64;

        MIUANA(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {
            int reg = registerOffset(offset);
            switch (reg) {
                case REG_60:
                    reg60 = value;
                    break;
                case REG_64:
                    reg64 = value;
                    break;
            }
        }

        @Override
        public long readRegister(long offset, boolean internal) {
            int reg = registerOffset(offset);
            switch (reg) {
                case REG_60:
                    return reg60;
                case REG_64:
                    return reg64;
                default:
                    return 0;
            }
        }

        static MIUANA miuana(GhidraScript script) {
            return new MIUANA(script, "miuana", MIUANA_START, MIUANA_END);
        }
    }

    static class MIUDIG extends Device {

        private static final long MIUDIG_START = 0x202200;
        private static final long MIUDIG_END = MIUDIG_START + 0x400;

        private static final int SOMESORTOFTRIGGER = 0x3c0;
        private static final int SOMESORTOFTRIGGER_TRIG = (1 << 0);
        private static final int SOMESORTOFTRIGGER_DONE = (1 << 15);

        MIUDIG(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        private long somesortoftrigger = 0;


        @Override
        public void writeRegister(long offset, long value) {
            int reg = registerOffset(offset);
            switch (reg) {
                case SOMESORTOFTRIGGER:
                    if ((value & SOMESORTOFTRIGGER_TRIG) != 0) {
                        script.printf("triggered!\n");
                        value |= SOMESORTOFTRIGGER_DONE;
                    }
                    somesortoftrigger = value;
                    break;
            }
        }

        @Override
        public long readRegister(long offset, boolean internal) {
            int reg = registerOffset(offset);
            switch (reg) {
                case SOMESORTOFTRIGGER:
                    return somesortoftrigger;
                default:
                    return 0;
            }
        }

        static MIUDIG miudig(GhidraScript script) {
            return new MIUDIG(script, "miudig", MIUDIG_START, MIUDIG_END);
        }
    }

    static class Memory extends Device {

        private HashMap<Long, Long> data = new HashMap<>();

        Memory(GhidraScript script, String name, long start, long end) {
            super(script, name, start, end);
        }

        @Override
        public void writeRegister(long offset, long value) {
            script.printf("Memory write: 0x%08x -> 0x%08x\n", offset, value);
            data.put(offset, value);
        }

        @Override
        public long readRegister(long offset, boolean internal) {
            long value = 0;
            if (data.containsKey(offset))
                value = data.get(offset);
            script.printf("Memory read: 0x%08x = 0x%08x\n", offset, value);
            return value;
        }

        static Memory sixtyFourMeg(GhidraScript script) {
            long size = 64 * (1024 * 1024);
            return new Memory(script, "DDR2", 0, size);
        }
    }

    private class Bus {
        private final String name;
        protected final long start;
        protected final long end;

        private final MemoryAccessFilter memoryAccessFilter;

        protected final List<Device> devices = new ArrayList<>();

        private boolean noisy = false;

        public void enableNoise() {
            noisy = true;
        }

        protected long accessOffsetFixUp(long offset) {
            return offset;
        }

        Bus(String name, long start, long end) {
            this.name = name;
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

                    off = accessOffsetFixUp(off);

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
                            if (noisy && !d.isMundane())
                                printf("%s Register read - %s:\t0x%08x = 0x%08x, size %d\n",
                                        name, d.name, riuOffset, value, size);
                            handled = true;
                            break;
                        }
                    }
                    if (!handled)
                        printf("%s Register unhandled read:\t0x%08x, size %d\n",
                                name, riuOffset, size);
                }

                @Override
                protected void processWrite(AddressSpace spc, long off, int size, byte[] values) {
                    if (!(off >= start && off < end))
                        return;

                    off = accessOffsetFixUp(off);

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
                            if (noisy && !d.isMundane())
                                printf("%s Register write - %s:\t0x%08x: 0x%08x -> 0x%08x, write size %d\n",
                                        name, d.name, riuOffset, currentValue, newValue, size);
                            d.writeRegister(riuOffset, newValue);

                            handled = true;
                            break;
                        }
                    if (!handled) {
                        long value = bytesToLong(values, size);
                        printf("%s Register unhandled write:\t0x%08x -> 0x%08x, write size %d\n",
                                name, riuOffset, value, size);
                    }
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

    /* A bus that wraps for a single device */
    class MemoryBus extends Bus {

        MemoryBus(String name, long start, long end) {
            super(name, start, end);
        }

        @Override
        protected long accessOffsetFixUp(long offset) {
            if (devices.size() != 1)
                return offset;

            Device d = devices.get(0);

            long mask = d.end - 1;

            //printf("o: %x, %x, %x, %x\n", offset, d.end, mask, (offset & mask));

            return (offset & mask) + start;
        }

        @Override
        public void registerDevice(Device device) {
            if (devices.size() != 0)
                throw new IllegalStateException("Only on device can be on memory bus\n");

            if (device.start != 0)
                throw new IllegalArgumentException("Device must start at 0\n");

            super.registerDevice(device);
        }
    }

    static long bytesToLong(byte[] bytes, int nbytes) {
        long value = 0;
        for (int i = 0; i < nbytes; i++)
            value |= ((long) bytes[i] & 0xffL) << (8 * i);
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

    enum ChipType {
        MSC8336,
        MSC313E,
        SSD201,
        SSD202D,
        SSD210,
    }

    @Override
    protected void run() throws Exception {

        ChipType chipType =
                askChoice("Chip Type", "Pick the target chip",
                        List.of(ChipType.values()), ChipType.SSD210);

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

        final long RIU_START = 0x1f000000;
        final long RIU_END = 0x20000000;
        Bus riu = new Bus("RIU", RIU_START, RIU_END);
        riu.enableNoise();
        riu.registerDevice(WDT.wdt(this));
        riu.registerDevice(Timer.timer0(this));
        riu.registerDevice(UART.pmUart(this));
        riu.registerDevice(CLKGEN.clkgen(this));
        riu.registerDevice(MPLL.mpll(this));
        riu.registerDevice(MIUPLL.miupll(this));
        riu.registerDevice(UPLL.upll0(this));
        riu.registerDevice(CPUPLL.cpupll(this));

        switch (chipType) {
            case MSC8336:
            case MSC313E:
                riu.registerDevice(CHIPTOP.chiptopMSC313E(this));
                break;
            case SSD201:
                riu.registerDevice(CHIPTOP.chiptopSSD201(this));
                break;
            case SSD202D:
                riu.registerDevice(CHIPTOP.chiptopSSD202D(this));
                break;
            case SSD210:
                riu.registerDevice(CHIPTOP.chiptopSSD210(this));
                break;
        }

        switch (chipType) {
            case MSC8336:
                riu.registerDevice(new MSC8336MYSTERY(this));
                riu.registerDevice(PADTOP.msc8336(this));
        }
        riu.registerDevice(EFUSE.efuse(this));
        riu.registerDevice(MAILBOX.mailbox(this));
        riu.registerDevice(MIUANA.miuana(this));
        riu.registerDevice(MIUDIG.miudig(this));

        final long MIU_START = 0x20000000;
        final long MIU_END = MIU_START + 0x20000000;
        Bus miu = new MemoryBus("MIU", MIU_START, MIU_END);
        miu.registerDevice(Memory.sixtyFourMeg(this));

        emulatorHelper.getEmulator().addMemoryAccessFilter(riu.getMemoryAccessFilter());
        emulatorHelper.getEmulator().addMemoryAccessFilter(miu.getMemoryAccessFilter());


        emulatorHelper.writeRegister("pc", 0xa0000000);

        while (!monitor.isCancelled()) {
            boolean noisy = false;

            if (noisy) {
                Address a = emulatorHelper.getExecutionAddress();
                long regR0 = emulatorHelper.readRegister("R0").longValue();
                long regR1 = emulatorHelper.readRegister("R1").longValue();

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